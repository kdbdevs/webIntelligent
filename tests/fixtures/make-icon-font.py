"""Optional fixture regeneration: pip install fonttools, then run this file.
An original geometric glyph, not a downloaded icon library. No runtime dependency.
"""
from pathlib import Path
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

font = FontBuilder(1000, isTTF=True)
font.setupGlyphOrder([".notdef", "diamond"])
font.setupCharacterMap({0xE001: "diamond"})
empty = TTGlyphPen(None)
pen = TTGlyphPen(None)
pen.moveTo((500, 900))
pen.lineTo((950, 450))
pen.lineTo((500, 0))
pen.lineTo((50, 450))
pen.closePath()
font.setupGlyf({".notdef": empty.glyph(), "diamond": pen.glyph()})
font.setupHorizontalMetrics({".notdef": (1000, 0), "diamond": (1000, 0)})
font.setupHorizontalHeader(ascent=950, descent=-50)
font.setupNameTable({"familyName": "FixtureIcon", "styleName": "Regular", "uniqueFontIdentifier": "WebIntelligent synthetic diamond", "fullName": "FixtureIcon Regular", "psName": "FixtureIcon-Regular"})
font.setupOS2(sTypoAscender=950, sTypoDescender=-50, usWinAscent=950, usWinDescent=50)
font.setupPost()
font.setupMaxp()
font.save(Path(__file__).with_name("icon.ttf"))
