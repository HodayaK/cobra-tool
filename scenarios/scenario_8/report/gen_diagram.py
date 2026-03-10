"""
Generate cobra-scenario-arch-8.png from the SVG diagram.
Requires: pip install cairosvg
Alternatively, open cobra-scenario-arch-8.svg in a browser and export/screenshot as PNG.
"""
from pathlib import Path

script_dir = Path(__file__).resolve().parent
svg_path = script_dir / "cobra-scenario-arch-8.svg"
png_path = script_dir / "cobra-scenario-arch-8.png"

try:
    import cairosvg
    cairosvg.svg2png(url=str(svg_path), write_to=str(png_path), output_width=900, output_height=520)
    print(f"Generated: {png_path}")
except ImportError:
    print("Install cairosvg to generate PNG: pip install cairosvg")
    print(f"Or open {svg_path} in a browser and save/export as PNG to {png_path}")
