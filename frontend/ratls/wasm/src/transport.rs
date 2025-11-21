#![cfg(target_arch = "wasm32")]

use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use futures::{FutureExt, StreamExt};
use js_sys::{ArrayBuffer, Uint8Array};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BinaryType, MessageEvent, WebSocket};

use ratls_core::RatlsError;

fn js_error(err: JsValue) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{err:?}"))
}

pub struct WasmWsStream {
    ws: WebSocket,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: Option<Vec<u8>>,
}

impl WasmWsStream {
    pub async fn connect(url: &str) -> Result<Self, RatlsError> {
        let ws =
            WebSocket::new(url).map_err(|e| RatlsError::Io(format!("websocket error: {e:?}")))?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let (open_tx, open_rx) = oneshot::channel();
        let mut open_tx = Some(open_tx);
        let open_cb = Closure::wrap(Box::new(move |_event: web_sys::Event| {
            if let Some(tx) = open_tx.take() {
                let _ = tx.send(());
            }
        }) as Box<dyn FnMut(_)>);
        ws.set_onopen(Some(open_cb.as_ref().unchecked_ref()));
        open_cb.forget();

        let (incoming_tx, incoming_rx) = mpsc::unbounded();
        let incoming_handle = incoming_tx.clone();
        let message_cb = Closure::wrap(Box::new(move |event: MessageEvent| {
            if let Ok(array_buf) = event.data().dyn_into::<ArrayBuffer>() {
                let array = Uint8Array::new(&array_buf);
                let mut data = vec![0u8; array.length() as usize];
                array.copy_to(&mut data);
                let _ = incoming_handle.unbounded_send(data);
            } else if let Ok(typed_array) = event.data().dyn_into::<Uint8Array>() {
                let mut data = vec![0u8; typed_array.length() as usize];
                typed_array.copy_to(&mut data);
                let _ = incoming_handle.unbounded_send(data);
            }
        }) as Box<dyn FnMut(_)>);
        ws.set_onmessage(Some(message_cb.as_ref().unchecked_ref()));
        message_cb.forget();

        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded::<Vec<u8>>();
        let ws_clone = ws.clone();
        spawn_local(async move {
            while let Some(payload) = outgoing_rx.next().await {
                if ws_clone.send_with_u8_array(&payload).is_err() {
                    break;
                }
            }
        });

        let (error_tx, error_rx) = oneshot::channel::<String>();
        let mut error_tx = Some(error_tx);
        let err_cb = Closure::wrap(Box::new(move |_event: web_sys::Event| {
            if let Some(tx) = error_tx.take() {
                let _ = tx.send("WebSocket connection failed".to_string());
            }
        }) as Box<dyn FnMut(_)>);
        ws.set_onerror(Some(err_cb.as_ref().unchecked_ref()));
        err_cb.forget();

        let open = open_rx.map(|res| res.map_err(|_| "websocket open cancelled".to_string()));
        let error = error_rx.map(|err| Err(err.unwrap_or_else(|_| "websocket error".into())));
        futures::pin_mut!(open, error);
        futures::select! {
            _ = open.fuse() => {},
            err = error.fuse() => {
                return Err(RatlsError::Io(err.unwrap_or_else(|_| "websocket failed".into())));
            }
        }

        Ok(Self {
            ws,
            incoming: incoming_rx,
            outgoing: outgoing_tx,
            read_buf: None,
        })
    }
}

impl AsyncRead for WasmWsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let Some(mut pending) = self.read_buf.take() {
            let to_copy = pending.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&pending[..to_copy]);
            if to_copy < pending.len() {
                pending.drain(0..to_copy);
                self.read_buf = Some(pending);
            }
            return Poll::Ready(Ok(to_copy));
        }

        match self.incoming.poll_next_unpin(cx) {
            Poll::Ready(Some(mut data)) => {
                let to_copy = data.len().min(buf.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    data.drain(0..to_copy);
                    self.read_buf = Some(data);
                }
                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WasmWsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.outgoing
            .unbounded_send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "websocket closed"))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let _ = cx;
        self.ws.close().map_err(js_error)?;
        Poll::Ready(Ok(()))
    }
}
