/**
 * The Reports page's built-in Markdown renderer. Reports are written by a
 * language model, so they are untrusted text: everything is escaped first and
 * only the constructs the report prompts produce come back as markup.
 *
 * @validates #output-encoding for #dashboard -- "Raw HTML in a report renders as text; javascript: and data: links render as plain text"
 */
import { describe, it, expect } from 'vitest';
import { renderMarkdown } from '../src/dashboard/markdown.js';

describe('renderMarkdown', () => {
  it('shows raw HTML in a report as text, never as markup', () => {
    const out = renderMarkdown('Hello <img src=x onerror=alert(1)> and <script>alert(1)</script>\n\n<b>bold?</b>');
    expect(out).not.toContain('<img');
    expect(out).not.toContain('<script');
    expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(out).toContain('&lt;b&gt;bold?&lt;/b&gt;');
  });

  it('keeps only safe link targets', () => {
    expect(renderMarkdown('[ok](https://example.com/a?b=1&c=2)')).toContain('<a href="https://example.com/a?b=1&amp;c=2" target="_blank" rel="noopener">ok</a>');
    expect(renderMarkdown('[in page](#exposures)')).toContain('<a href="#exposures">in page</a>');
    expect(renderMarkdown('[bad](javascript:alert(1))')).not.toContain('<a');
    expect(renderMarkdown('[bad](data:text/html,x)')).not.toContain('<a');
  });

  it('renders the constructs the report prompts produce', () => {
    const out = renderMarkdown([
      '# Title', '', 'Some **bold**, *em* and `code <x>`.', '',
      '- one', '- two', '  - nested', '', '1. first', '2. second', '',
      '| A | B |', '|---|---|', '| `#api` | x |', '',
      '```mermaid', 'graph LR', '  a --> b', '```', '', '> quoted', '', '---',
    ].join('\n'));
    expect(out).toContain('<h1>Title</h1>');
    expect(out).toContain('<strong>bold</strong>');
    expect(out).toContain('<em>em</em>');
    expect(out).toContain('<code>code &lt;x&gt;</code>');
    expect(out).toMatch(/<ul><li>one<\/li><li>two<ul><li>nested<\/li><\/ul><\/li><\/ul>/);
    expect(out).toContain('<ol><li>first</li><li>second</li></ol>');
    expect(out).toContain('<th>A</th><th>B</th>');
    expect(out).toContain('<td><code>#api</code></td>');
    // A Mermaid fence is shown as its source: the page renders no Mermaid.
    expect(out).toContain('<pre data-lang="mermaid"><code>graph LR\n  a --&gt; b</code></pre>');
    expect(out).toContain('<blockquote><p>quoted</p></blockquote>');
    expect(out).toContain('<hr>');
  });
});
