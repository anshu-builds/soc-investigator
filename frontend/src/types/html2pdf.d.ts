declare module 'html2pdf.js' {
  interface Html2PdfOptions {
    margin?: number | number[]
    filename?: string
    image?: { type?: string; quality?: number }
    html2canvas?: Record<string, unknown>
    jsPDF?: { unit?: string; format?: string; orientation?: string }
    pagebreak?: { mode?: string[]; before?: string | string[]; after?: string | string[]; avoid?: string | string[] }
  }

  interface Html2PdfInstance {
    set(options: Html2PdfOptions): Html2PdfInstance
    from(element: HTMLElement): Html2PdfInstance
    save(): Promise<void>
    toPdf(): Html2PdfInstance
    output(type: string): Promise<unknown>
  }

  function html2pdf(): Html2PdfInstance

  export default html2pdf
}
