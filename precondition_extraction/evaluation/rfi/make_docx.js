const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
        WidthType, AlignmentType, LevelFormat, ExternalHyperlink } = require('docx');

const src = fs.readFileSync(process.argv[2], 'utf8');
const lines = src.split('\n');

// Inline: **bold**, *italic*, `code`, <url>, [text](url). Returns TextRun/Hyperlink children.
function inline(text) {
  const out = [];
  const re = /(\*\*[^*]+\*\*)|(\*[^*]+\*)|(`[^`]+`)|(<https?:\/\/[^>]+>)|(\[[^\]]+\]\([^)]+\))/g;
  let last = 0, m;
  const push = (t, o = {}) => { if (t) out.push(new TextRun({ text: t, ...o })); };
  while ((m = re.exec(text)) !== null) {
    push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('**'))      push(tok.slice(2, -2), { bold: true });
    else if (tok.startsWith('`'))  push(tok.slice(1, -1), { font: 'Consolas' });
    else if (tok.startsWith('*'))  push(tok.slice(1, -1), { italics: true });
    else if (tok.startsWith('<'))  { const u = tok.slice(1, -1);
      out.push(new ExternalHyperlink({ children: [new TextRun({ text: u, style: 'Hyperlink' })], link: u })); }
    else { const mm = /\[([^\]]+)\]\(([^)]+)\)/.exec(tok);
      out.push(new ExternalHyperlink({ children: [new TextRun({ text: mm[1], style: 'Hyperlink' })], link: mm[2] })); }
    last = m.index + tok.length;
  }
  push(text.slice(last));
  return out.length ? out : [new TextRun('')];
}

const kids = [];
const P = (t, o = {}) => kids.push(new Paragraph({ children: inline(t), spacing: { after: 160 }, ...o }));

function table(rows) {
  const cells = rows.map(r => r.replace(/^\||\|$/g, '').split('|').map(c => c.trim()));
  const body = cells.filter(r => !r.every(c => /^:?-+:?$/.test(c)));
  const n = Math.max(...body.map(r => r.length));
  const total = 9360, w = Math.floor(total / n);
  kids.push(new Table({
    columnWidths: Array(n).fill(w),
    rows: body.map((r, i) => new TableRow({
      children: Array.from({ length: n }, (_, j) => new TableCell({
        width: { size: w, type: WidthType.DXA },
        children: [new Paragraph({ children: inline(r[j] || ''), spacing: { before: 60, after: 60 } })],
      })),
      tableHeader: i === 0,
    })),
  }));
  kids.push(new Paragraph({ text: '', spacing: { after: 160 } }));
}

let i = 0, para = [];
const flush = () => { if (para.length) { P(para.join(' ')); para = []; } };

while (i < lines.length) {
  const ln = lines[i];
  if (/^\s*$/.test(ln)) { flush(); i++; continue; }
  if (/^---+$/.test(ln.trim())) { flush(); i++; continue; }          // horizontal rules dropped
  if (ln.startsWith('|')) {                                          // table block
    flush(); const rows = [];
    while (i < lines.length && lines[i].startsWith('|')) rows.push(lines[i++]);
    table(rows); continue;
  }
  let m;
  if ((m = /^(#{1,3})\s+(.*)$/.exec(ln))) {
    flush();
    const lvl = [HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3][m[1].length - 1];
    kids.push(new Paragraph({ children: inline(m[2]), heading: lvl, spacing: { before: 320, after: 160 } }));
    i++; continue;
  }
  if ((m = /^>\s?(.*)$/.exec(ln))) {                                 // blockquote -> indented para
    flush(); const buf = [];
    while (i < lines.length && /^>/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
    P(buf.join(' ').trim(), { indent: { left: 480 } }); continue;
  }
  if ((m = /^\s*-\s+(.*)$/.exec(ln))) {                              // bullet (incl. checklists)
    flush(); const buf = [m[1]]; i++;
    while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*-\s/.test(lines[i])) buf.push(lines[i++].trim());
    let t = buf.join(' ').replace(/^\[[ x]\]\s*/, '');
    kids.push(new Paragraph({ children: inline(t), bullet: { level: 0 }, spacing: { after: 120 } }));
    continue;
  }
  para.push(ln.trim()); i++;
}
flush();

const doc = new Document({
  styles: { default: {
    document: { run: { font: 'Calibri', size: 22 }, paragraph: { spacing: { line: 276 } } },
    heading1: { run: { font: 'Calibri', size: 32, bold: true, color: '000000' } },
    heading2: { run: { font: 'Calibri', size: 26, bold: true, color: '000000' } },
    heading3: { run: { font: 'Calibri', size: 23, bold: true, color: '000000' } },
  }},
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    children: kids,   // no headers, no footers
  }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(process.argv[3], b); console.log('wrote', process.argv[3], b.length, 'bytes'); });
