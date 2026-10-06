import AppKit

let size = NSSize(width: 256, height: 256)
let image = NSImage(size: size, flipped: false) { rect in
    let bounds = rect.insetBy(dx: 4, dy: 4)
    let path = NSBezierPath(roundedRect: bounds, xRadius: 56, yRadius: 56)
    NSColor(srgbRed: 0.09, green: 0.43, blue: 0.96, alpha: 1).setFill()
    path.fill()
    let config = NSImage.SymbolConfiguration(pointSize: 132, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))
    if let symbol = NSImage(systemSymbolName: "network", accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let side: CGFloat = 148
        let origin = NSPoint(x: (rect.width - side) / 2, y: (rect.height - side) / 2 - 2)
        symbol.draw(in: NSRect(origin: origin, size: NSSize(width: side, height: side)))
    }
    return true
}

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fputs("failed to encode png\n", stderr)
    exit(1)
}
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon.png"
try png.write(to: URL(fileURLWithPath: out))
