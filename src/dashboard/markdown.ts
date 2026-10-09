/**
 * GuardLink Dashboard — the Markdown the Reports page renders, at generation time.
 *
 * Threat reports are Markdown written by a language model, so the renderer
 * treats them as untrusted text: every character is HTML-escaped FIRST, and
 * only the constructs below are turned back into markup. Raw HTML in a report
 * is shown as text, never parsed. Links keep only `http(s):`, `mailto:`,
 * in-page `#` and relative targets; anything else (`javascript:`, `data:`)
 * renders as plain text.
 *
 * Supported: ATX headings, paragraphs, emphasis and strong, inline code,
 * fenced code blocks (including ```mermaid, shown as source), block quotes,
 * ordered and unordered lists with nesting by indentation, pipe tables,
 * horizontal rules and links. That is what the report prompts produce; the
 * page does not need a general CommonMark engine, and does not load one.
 *
 * @mitigates #dashboard against #xss using #output-encoding -- "renderMarkdown escapes the whole report before adding markup back; link targets are allow-listed by scheme"
 * @flows SavedReport -> #dashboard via renderMarkdown -- "Threat-report prose rendered to HTML at generation time"
 * @comment -- "Replaces the CDN copy of marked: the page makes no network request to render a report"
 */

const escHtml = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function safeHref(raw: string): string | null {
  const href = raw.trim();
  if (/^(https?:|mailto:)/i.test(href) || href.startsWith('#') || /^[./\w-][^:]*$/.test(href)) return href;
  return null;
}

/** Inline constructs over ESCAPED text. Code spans are cut out first so nothing inside them is transformed. */
function inline(text: string): string {
  const codes: string[] = [];
  // A code span becomes a placeholder no report can contain (a private-use character), restored last.
  let s = text.replace(/\uE000/g, '').replace(/`([^`]+)`/g, (_, c: string) => { codes.push(c); return `\uE000${codes.length - 1}\uE000`; });
  s = escHtml(s);
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (whole, label: string, url: string) => {
    const href = safeHref(url.replace(/&amp;/g, '&'));
    return href ? `<a href="${escHtml(href)}"${/^https?:/i.test(href) ? ' target="_blank" rel="noopener"' : ''}>${label}</a>` : label;
  });
  s = s.replace(/\*\*([^*]+)\*\*|__([^_]+)__/g, (_, a?: string, b?: string) => `<strong>${a ?? b}</strong>`);
  s = s.replace(/(^|[^*\w])\*([^*\s][^*]*)\*(?!\w)|(^|[^_\w])_([^_\s][^_]*)_(?!\w)/g, (_, p1?: string, a?: string, p3?: string, b?: string) => `${p1 ?? p3 ?? ''}<em>${a ?? b}</em>`);
  return s.replace(/\uE000(\d+)\uE000/g, (_, i: string) => `<code>${escHtml(codes[Number(i)])}</code>`);
}

const isTableSep = (l: string): boolean => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l);
const cells = (l: string): string[] => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
const listItem = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;

export function renderMarkdown(src: string): string {
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  const out: string[] = [];
  let i = 0;
  const para: string[] = [];
  const flush = (): void => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para.length = 0; } };

  const list = (): string => {
    // Items at the indentation of the first line; deeper lines nest.
    const base = (listItem.exec(lines[i])![1] ?? '').length;
    const ordered = /\d/.test(listItem.exec(lines[i])![2]);
    const items: string[] = [];
    while (i < lines.length) {
      const m = listItem.exec(lines[i]);
      if (!m || m[1].length < base) break;
      if (m[1].length > base) { items[items.length - 1] = (items[items.length - 1] ?? '') + list(); continue; }
      let body = inline(m[3]);
      i++;
      // Continuation lines: indented text that is not a new item.
      while (i < lines.length && lines[i].trim() && !listItem.test(lines[i]) && /^\s+/.test(lines[i])) { body += ` ${inline(lines[i].trim())}`; i++; }
      items.push(body);
    }
    return `<${ordered ? 'ol' : 'ul'}>${items.map(b => `<li>${b}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`;
  };

  while (i < lines.length) {
    const line = lines[i];
    const fence = /^\s*(```|~~~)\s*([\w-]*)\s*$/.exec(line);
    if (fence) {
      flush();
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      out.push(`<pre${fence[2] ? ` data-lang="${escHtml(fence[2])}"` : ''}><code>${escHtml(body.join('\n'))}</code></pre>`);
      continue;
    }
    if (!line.trim()) { flush(); i++; continue; }
    const h = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
    if (h) { flush(); out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); i++; continue; }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { flush(); out.push('<hr>'); i++; continue; }
    if (/^\s*>/.test(line)) {
      flush();
      const q: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ''));
      out.push(`<blockquote>${renderMarkdown(q.join('\n'))}</blockquote>`);
      continue;
    }
    if (line.includes('|') && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      flush();
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) rows.push(cells(lines[i++]));
      out.push(`<div class="table-wrap"><table class="tbl"><thead><tr>${head.map(c => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${head.map((_, k) => `<td>${inline(r[k] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    if (listItem.test(line)) { flush(); out.push(list()); continue; }
    para.push(line.trim());
    i++;
  }
  flush();
  return out.join('\n');
}
