with open('frontend/src/components/KaliTerminal.tsx', 'r', encoding='utf-8') as f:
    c = f.read()

c_norm = c.replace('\r\n', '\n')

old_pills = """            <div className="flex flex-wrap items-center gap-1.5">
              {PRACTICE_SCRIPT_CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => setPracticeCategoryFilter(cat.id)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer border ${
                    practiceCategoryFilter === cat.id
                      ? 'bg-zinc-800 text-white border-white font-bold'
                      : 'bg-zinc-950 text-zinc-300 border-zinc-800 hover:text-white hover:border-zinc-700'
                  }`}
                >
                  <span>{cat.label}</span>
                  <span className="ml-1 opacity-70">({cat.count})</span>
                </button>
              ))}
            </div>"""

new_pills = """            <div className="flex items-center justify-between text-[11px] font-mono px-2.5 py-1 rounded bg-zinc-950/80 border border-zinc-800 text-zinc-400">
              <span>Directory: <strong className="text-cyan-300">~/target-assessment/Practice_Scripts/</strong></span>
              <span className="text-zinc-500">407 modular scripts &bull; 0 subdirectories</span>
            </div>"""

old_badge = """                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-900 text-zinc-300 border border-zinc-800">
                      {script.category}
                    </span>"""

new_badge = """                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/40">
                      Practice_Scripts
                    </span>"""

old_prog = """          <span className="text-zinc-300 shrink-0 text-[11px] font-mono truncate max-w-[240px]">
            {practiceScanProgress.category}/{practiceScanProgress.scriptName}
          </span>"""

new_prog = """          <span className="text-zinc-300 shrink-0 text-[11px] font-mono truncate max-w-[240px]">
            Practice_Scripts/{practiceScanProgress.scriptName.replace(/^Practice_Scripts\\//, '')}
          </span>"""

assert old_pills in c_norm, 'old_pills not found'
assert old_badge in c_norm, 'old_badge not found'
assert old_prog in c_norm, 'old_prog not found'

c_norm = c_norm.replace(old_pills, new_pills)
c_norm = c_norm.replace(old_badge, new_badge)
c_norm = c_norm.replace(old_prog, new_prog)

with open('frontend/src/components/KaliTerminal.tsx', 'w', encoding='utf-8') as f:
    f.write(c_norm)

print('KaliTerminal.tsx updated successfully!')
