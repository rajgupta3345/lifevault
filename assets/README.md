# LifeVault Logo Kit

**Concept:** a shield (protection) holding a combination dial (the vault), opened left
and right so an ECG lifeline (life) runs straight through it.

Palette matches the app theme in `main.py`: `#0A1120` / `#123554` navy,
`#1D6B91` mid blue, `#06B6D4` → `#67E8F9` → `#A5F3FC` cyan ramp.

## Files

| File | Use |
| --- | --- |
| `lifevault-logo.svg` | Primary mark, 128×128, scalable |
| `lifevault-logo-lockup.svg` | Horizontal lockup: mark + "LifeVault" + tagline |
| `lifevault-favicon.svg` | Simplified mark (no dial scale) for tiny sizes |
| `lifevault-logo-{16,32,64,128,256,512}.png` | Transparent-background mark, exact pixel sizes |
| `lifevault-favicon-{16,32,48}.png` | Transparent favicon PNGs |
| `lifevault-app-icon-512.png` | Rounded app tile (gradient background) |
| `lifevault-lockup.png` | Lockup on transparent background, 1332×420 (3×) |
| `lifevault-lockup-dark.png` | Lockup on `#0B1220`, 1332×420 (3×) |
| `preview.html` | Visual spec sheet — open in a browser to review |
| `export-png.ps1` | Re-runs the PNG export after editing the SVGs |

## Regenerating PNGs

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File assets\export-png.ps1
```

Uses headless Chrome (installed with Chrome or Edge) to rasterize the SVGs with
transparent backgrounds.

## Usage notes

- Use `lifevault-favicon.svg` / `-16/-32/-48.png` below 64 px — the full dial scale
  gets muddy at small sizes.
- The dark navy shield reads on both light and dark backgrounds; the cyan outline
  keeps it visible on `#0B1220`.
- Wordmark: "Life" in `#0F172A` (light UI) or `#FFFFFF` (dark UI), "Vault" in
  `#0891B2` / `#67E8F9`, tagline in `#64748B` / `#7DD3FC`.
