# AgentKeys brand assets

This folder contains the project logo set. The canonical source is the vector
file `agentkeys-logo.svg`; every PNG / ICO variant below is rendered from it.
All generated logo and icon variants use transparent backgrounds.

Theme naming:

- `light` assets use a black mark for light surfaces.
- `dark` assets use a white mark for dark surfaces.
- Unsuffixed assets are transparent light-theme fallbacks for conventional filenames.

## Files

- `agentkeys-logo.svg` - canonical vector source (edit this, then re-render the set).
- `agentkeys-logo-source.png` - 1024px raster of the canonical source.
- `agentkeys-logo-light-1024.png`, `agentkeys-logo-light-512.png`, `agentkeys-logo-light-256.png` - transparent light-theme logos.
- `agentkeys-logo-dark-1024.png`, `agentkeys-logo-dark-512.png`, `agentkeys-logo-dark-256.png` - transparent dark-theme logos.
- `agentkeys-logo-1024.png`, `agentkeys-logo-512.png`, `agentkeys-logo-256.png` - transparent light-theme fallback logos.
- `favicon-light.ico`, `favicon-dark.ico`, `favicon.ico` - multi-size browser favicons.
- `favicon-light-16x16.png`, `favicon-light-32x32.png`, `favicon-light-48x48.png` - transparent light-theme favicon PNGs.
- `favicon-dark-16x16.png`, `favicon-dark-32x32.png`, `favicon-dark-48x48.png` - transparent dark-theme favicon PNGs.
- `favicon-16x16.png`, `favicon-32x32.png`, `favicon-48x48.png` - transparent light-theme fallback favicon PNGs.
- `apple-touch-icon-light.png`, `apple-touch-icon-dark.png`, `apple-touch-icon.png` - transparent 180px touch icons.
- `android-chrome-light-192x192.png`, `android-chrome-light-512x512.png` - transparent light-theme web app icons.
- `android-chrome-dark-192x192.png`, `android-chrome-dark-512x512.png` - transparent dark-theme web app icons.
- `android-chrome-192x192.png`, `android-chrome-512x512.png` - transparent light-theme fallback web app icons.
- `site.webmanifest` - minimal web manifest that references the generated app icons.

For HTML pages, use:

```html
<link rel="icon" href="docs/assets/brand/favicon-light.ico" sizes="any" media="(prefers-color-scheme: light)">
<link rel="icon" href="docs/assets/brand/favicon-dark.ico" sizes="any" media="(prefers-color-scheme: dark)">
<link rel="icon" href="docs/assets/brand/favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="docs/assets/brand/favicon-light-32x32.png" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="32x32" href="docs/assets/brand/favicon-dark-32x32.png" media="(prefers-color-scheme: dark)">
<link rel="apple-touch-icon" href="docs/assets/brand/apple-touch-icon-light.png" media="(prefers-color-scheme: light)">
<link rel="apple-touch-icon" href="docs/assets/brand/apple-touch-icon-dark.png" media="(prefers-color-scheme: dark)">
<link rel="manifest" href="docs/assets/brand/site.webmanifest">
```

For inline display, use:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/agentkeys-logo-dark-512.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/brand/agentkeys-logo-light-512.png">
  <img src="docs/assets/brand/agentkeys-logo-light-512.png" width="140" alt="AgentKeys logo">
</picture>
```
