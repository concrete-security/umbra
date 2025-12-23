let pdfjsPromise: Promise<any> | null = null

async function ensureWorker(pdfjs: any) {
  if (typeof window === "undefined") {
    return
  }

  const workerUrl = `${window.location.origin}/pdfjs/pdf.worker.mjs`
  if (pdfjs?.GlobalWorkerOptions) {
    pdfjs.GlobalWorkerOptions.workerSrc = workerUrl
  }
}

export async function loadPdfjs() {
  if (!pdfjsPromise) {
    const moduleUrl = `${window.location.origin}/pdfjs/pdf.mjs`
    pdfjsPromise = import(/* webpackIgnore: true */ moduleUrl)
  }
  const pdfjs = await pdfjsPromise
  await ensureWorker(pdfjs)
  return pdfjs
}
