from pathlib import Path

p = Path('frontend/src/components/KaliTerminal.tsx')
text = p.read_text(encoding='utf-8')
text_clean = text.replace('\r\n', '\n')

old_block = """          if (log.type === 'error') {
            return (
              <div key={log.id} className="text-red-400 whitespace-pre-wrap">
                {log.content}
              </div>
            );
          }
          if (log.type === 'success') {
            return (
              <div key={log.id} className="text-white whitespace-pre-wrap font-semibold">
                {log.content}
              </div>
            );
          }
          if (log.type === 'system') {
            return (
              <div key={log.id} className="text-zinc-400 whitespace-pre-wrap">
                {log.content}
              </div>
            );
          }
          return (
            <div key={log.id} className="text-white whitespace-pre-wrap">
              {log.content}
            </div>
          );"""

new_block = """          let lineClass = 'text-white';
          if (log.type === 'error') {
            lineClass = 'text-red-400';
          } else if (log.content.includes('[!] >>> BUG IDENTIFIED')) {
            lineClass = 'text-rose-400 font-bold';
          } else if (log.content.includes('[Script Response Proof]')) {
            lineClass = 'text-amber-300 font-semibold';
          } else if (log.content.includes('[PROOF #')) {
            lineClass = 'text-emerald-400 font-bold';
          } else if (log.content.includes('EMPIRICAL SCRIPT RESPONSES & PROOF DOSSIER')) {
            lineClass = 'text-cyan-300 font-bold';
          } else if (log.content.includes('│     >>>')) {
            lineClass = 'text-amber-300 font-medium';
          } else if (log.content.includes('│   Script CLI Command:') || log.content.includes('│   Reproduction Command:')) {
            lineClass = 'text-emerald-300 font-medium';
          } else if (log.content.includes('│   Target Wire Response:')) {
            lineClass = 'text-sky-300 font-medium';
          } else if (log.content.includes('│   Observed Script Proof:')) {
            lineClass = 'text-yellow-200 font-semibold';
          } else if (log.type === 'success') {
            lineClass = 'text-white whitespace-pre-wrap font-semibold';
          } else if (log.type === 'system') {
            lineClass = 'text-zinc-400';
          }

          return (
            <div key={log.id} className={`${lineClass} whitespace-pre-wrap`}>
              {log.content}
            </div>
          );"""

if old_block in text_clean:
    new_text = text_clean.replace(old_block, new_block)
    if '\r\n' in text:
        new_text = new_text.replace('\n', '\r\n')
    p.write_text(new_text, encoding='utf-8')
    print("SUCCESS: Updated log rendering in KaliTerminal.tsx")
else:
    print("ERROR: old_block not found in KaliTerminal.tsx")

