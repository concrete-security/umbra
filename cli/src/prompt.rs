//! Interactive yes/no consent, shared by every command that must ask before
//! doing something the user cannot undo.

use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

/// Tries the user gets to type a usable answer before the question is dropped.
pub const MAX_ATTEMPTS: usize = 3;

/// How long one try waits for a line. A prompt must never outlive the patience
/// of whatever is waiting on the command: `umbra tunnel` asks while it is an
/// SSH `ProxyCommand`, so a prompt nobody answers would hang the ssh client --
/// and everything driving it -- for as long as the terminal stays open. Three
/// tries make the worst case three times this.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// Ask `question` on the controlling terminal, appending the `[y/n] ` hint.
/// `Some` carries the typed answer; `None` means no usable answer arrived -- no
/// terminal, EOF (Ctrl-D), silence past [`ANSWER_TIMEOUT`], or the tries ran
/// out -- and the caller MUST then treat the question as unasked, take no
/// action, and record no preference.
///
/// Prefers `/dev/tty` over stdin so `umbra tunnel` can still ask while its
/// stdin is an SSH `ProxyCommand` byte stream.
pub fn confirm(question: &str) -> Option<bool> {
    #[cfg(unix)]
    {
        use std::{fs::OpenOptions, os::fd::AsRawFd};

        if let Ok(tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
            if let Ok(mut out) = tty.try_clone() {
                let fd = tty.as_raw_fd();
                return ask(|| read_line(fd), &mut out, question);
            }
        }
        if io::stdin().is_terminal() && io::stderr().is_terminal() {
            let fd = io::stdin().as_raw_fd();
            return ask(|| read_line(fd), &mut io::stderr(), question);
        }
        None
    }
    #[cfg(not(unix))]
    {
        // No timed read here: the hazard a timeout guards -- a prompt hanging
        // an SSH `ProxyCommand` -- needs a controlling terminal to begin with.
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return None;
        }
        ask(
            || {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) => None,
                    Err(err) if err.kind() == io::ErrorKind::InvalidData => Some(String::new()),
                    Err(_) => None,
                    Ok(_) => Some(line),
                }
            },
            &mut io::stderr(),
            question,
        )
    }
}

/// Read one line from `fd`, waiting at most [`ANSWER_TIMEOUT`]. `None` when the
/// wait elapses, the stream ends, or it fails; undecodable bytes yield an empty
/// line instead, since a present user can retype them.
///
/// Reads one byte at a time and stops at the newline so that **nothing typed
/// after the answer is consumed**: the terminal usually stays in use once the
/// prompt is done -- `umbra tunnel` goes on to relay it to an SSH session --
/// and a buffered read, or a reader left running on another thread, would eat
/// keystrokes that belong to whatever comes next.
#[cfg(unix)]
fn read_line(fd: std::os::fd::RawFd) -> Option<String> {
    read_line_before(fd, Instant::now() + ANSWER_TIMEOUT)
}

#[cfg(unix)]
fn read_line_before(fd: std::os::fd::RawFd, deadline: Instant) -> Option<String> {
    let mut line = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || !wait_readable(fd, remaining) {
            return None;
        }
        let mut byte = 0u8;
        // SAFETY: `fd` is an open descriptor for the duration of the call and
        // the kernel writes at most the one byte pointed at.
        match unsafe { libc::read(fd, std::ptr::addr_of_mut!(byte).cast(), 1) } {
            1 if byte == b'\n' => break,
            1 => line.push(byte),
            0 => return None,
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            _ => return None,
        }
    }
    Some(String::from_utf8(line).unwrap_or_default())
}

/// Block until `fd` has input or `timeout` elapses. Signals that merely
/// interrupt the wait (a terminal resize, say) do not end it.
#[cfg(unix)]
fn wait_readable(fd: std::os::fd::RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialised `pollfd` is passed, matching the length.
        match unsafe {
            libc::poll(
                &mut poll_fd,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        } {
            1 => return true,
            0 => return false,
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
            _ => return false,
        }
    }
}

/// Drive the question over one already-chosen terminal channel. There is no
/// default answer: an empty line is as unusable as any other typo, so consent
/// is always typed.
fn ask(
    mut next_line: impl FnMut() -> Option<String>,
    out: &mut impl Write,
    question: &str,
) -> Option<bool> {
    for tries_left in (1..=MAX_ATTEMPTS).rev() {
        let _ = write!(
            out,
            "{}",
            crate::style::info_line(&prompt_line(question, tries_left))
        );
        let _ = out.flush();
        match next_line()?.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Some(true),
            "n" | "no" => return Some(false),
            _ => continue,
        }
    }
    None
}

/// Render the question, or the retry line that counts down the tries left.
fn prompt_line(question: &str, tries_left: usize) -> String {
    if tries_left == MAX_ATTEMPTS {
        format!("{question} [y/n] ")
    } else {
        format!(
            "Answer y or n -- {tries_left} {} left, or {} to cancel. [y/n] ",
            if tries_left == 1 { "try" } else { "tries" },
            if cfg!(unix) {
                "Ctrl-D"
            } else {
                "Ctrl-Z + Enter"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Drive `ask` over a scripted terminal, returning the answer plus
    /// everything the user would have seen, so tests pin the rendered prompts
    /// too. An empty line stands for input that could not be decoded, which is
    /// what the readers yield for it.
    fn run(typed: &[&str]) -> (Option<bool>, String) {
        let mut typed = typed.iter();
        let mut shown = Vec::new();
        let answer = ask(
            || typed.next().map(|line| (*line).to_string()),
            &mut shown,
            "Install?",
        );
        (answer, String::from_utf8(shown).expect("utf-8 prompts"))
    }

    /// Only y/yes/n/no in any ASCII case count as an answer; a typo -- including
    /// input that could not be decoded, which a present user can retype --
    /// costs one try and the question can still be answered afterwards.
    #[rstest]
    #[case::yes(&["y"], true)]
    #[case::yes_word(&[" YES "], true)]
    #[case::yes_mixed_case(&["YEs"], true)]
    #[case::no(&["n"], false)]
    #[case::no_word(&["No"], false)]
    #[case::typo_then_yes(&["fhg", "y"], true)]
    #[case::empty_is_a_typo(&["", "y"], true)]
    #[case::two_typos_then_no(&["2", "fjhb", "no"], false)]
    fn ask_answer_success(#[case] typed: &[&str], #[case] expected: bool) {
        assert_eq!(run(typed).0, Some(expected));
    }

    /// Nothing usable means no answer at all: exhausted tries and a stream that
    /// yields nothing -- EOF, or silence past the timeout -- both give `None`,
    /// and a dead stream does not burn the remaining tries.
    #[rstest]
    #[case::three_typos(&["fhg", "2", "fjhb"], 3)]
    #[case::three_empty_lines(&["", "", ""], 3)]
    #[case::nothing_at_once(&[], 1)]
    #[case::typo_then_nothing(&["fhg"], 2)]
    fn ask_answer_failure(#[case] typed: &[&str], #[case] asks: usize) {
        let (answer, shown) = run(typed);
        assert_eq!(answer, None);
        assert_eq!(shown.matches("[y/n] ").count(), asks);
    }

    /// The user must see the question first, then a countdown that reads
    /// correctly in the singular on the last try.
    #[test]
    fn ask_renders_question_then_countdown() {
        assert_eq!(
            run(&["fhg", "2", "fjhb"]).1,
            "Install? [y/n] \
             Answer y or n -- 2 tries left, or Ctrl-D to cancel. [y/n] \
             Answer y or n -- 1 try left, or Ctrl-D to cancel. [y/n] "
        );
    }

    /// The reader takes the answer and NOT a byte more: whatever the user typed
    /// after it stays on the terminal for the next reader, which is what keeps
    /// a prompt from eating the SSH session `umbra tunnel` goes on to relay.
    #[cfg(unix)]
    #[test]
    fn read_line_before_leaves_later_input_success() {
        use std::{io::Write as _, os::fd::AsRawFd, os::unix::net::UnixStream};

        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        writer.write_all(b"y\nSECOND\n").expect("write");
        let far = Instant::now() + Duration::from_secs(30);

        assert_eq!(read_line_before(reader.as_raw_fd(), far), Some("y".into()));
        assert_eq!(
            read_line_before(reader.as_raw_fd(), far),
            Some("SECOND".into())
        );
    }

    /// A user who never answers must not pin the command: the read gives up on
    /// its deadline. Closed input (Ctrl-D) gives up at once.
    #[cfg(unix)]
    #[rstest]
    #[case::silence(false)]
    #[case::closed_input(true)]
    fn read_line_before_no_answer_failure(#[case] close: bool) {
        use std::{os::fd::AsRawFd, os::unix::net::UnixStream};

        let (reader, writer) = UnixStream::pair().expect("socket pair");
        if close {
            drop(writer);
        }
        let started = Instant::now();
        let deadline = started + Duration::from_millis(120);

        assert_eq!(read_line_before(reader.as_raw_fd(), deadline), None);
        // Silence must wait for its deadline; a closed stream must not.
        assert_eq!(started.elapsed() >= Duration::from_millis(100), !close);
    }
}
