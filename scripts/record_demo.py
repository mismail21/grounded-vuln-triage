"""Record docs/demo.gif by driving the running web UI with headless Chrome.

    uvicorn triage.server:app &        # with a model key in .env
    python scripts/record_demo.py [--mode agent|baseline]
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent.parent / "docs" / "demo.gif"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--mode", default="agent", choices=["agent", "baseline"])
    ap.add_argument("--example", default="package.json example")
    args = ap.parse_args()

    frames: list[tuple[Image.Image, int]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width": 1180, "height": 760}, color_scheme="dark")

        def snap(ms: int) -> None:
            img = Image.open(io.BytesIO(page.screenshot())).convert("RGB")
            frames.append((img, ms))

        page.goto(args.url)
        page.wait_for_selector("textarea")
        snap(1800)
        page.get_by_role("button", name=args.example).click()
        snap(1500)
        page.get_by_label("Baseline (no AI)" if args.mode == "baseline" else "AI agent").check()
        page.get_by_role("button", name="Scan dependencies").click()
        page.wait_for_timeout(600)
        snap(1600)
        page.wait_for_selector(".stats", timeout=300_000)
        page.wait_for_timeout(500)
        snap(2500)
        for _ in range(3):
            page.mouse.wheel(0, 420)
            page.wait_for_timeout(400)
            snap(1700)
        if page.locator("details summary").count():
            page.locator("details summary").click()
            page.wait_for_timeout(300)
            page.keyboard.press("End")
            page.wait_for_timeout(400)
            snap(2600)
        browser.close()

    OUT.parent.mkdir(exist_ok=True)
    width = 960
    imgs = [f.resize((width, int(f.height * width / f.width)), Image.LANCZOS) for f, _ in frames]
    pal = [im.quantize(colors=128, method=Image.Quantize.MEDIANCUT) for im in imgs]
    pal[0].save(OUT, save_all=True, append_images=pal[1:], duration=[d for _, d in frames], loop=0, optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
