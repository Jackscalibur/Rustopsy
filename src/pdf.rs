use printpdf::*;
use std::fs::File;
use std::io::BufWriter;
use crate::binary::ELFBinary;

pub fn generate_pdf_report(binary: &ELFBinary, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create a new PDF document
    let (doc, page1, layer1) = PdfDocument::new("Binary Analysis Report", 
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Binary Analysis"
    );

    // Get the current layer
    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Add title
    let font = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    current_layer.use_text(format!("Binary Analysis Report: {}", binary.path.display()), 
        24.0, // font size
        Mm(10.0), // x position
        Mm(287.0), // y position from bottom
        &font
    );

    // Add architecture info
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    current_layer.use_text(format!("Architecture: {:?}", binary.architecture),
        12.0,
        Mm(10.0),
        Mm(267.0),
        &font
    );

    // Add security features
    let mut y_pos = 247.0;
    current_layer.use_text("Security Features:", 14.0, Mm(10.0), Mm(y_pos), &font);
    y_pos -= 20.0;

    // RELRO
    current_layer.use_text(format!("• RELRO: {:?}", binary.security_features.relro),
        12.0,
        Mm(20.0),
        Mm(y_pos),
        &font
    );
    y_pos -= 20.0;

    // PIE
    current_layer.use_text(format!("• PIE: {:?}", binary.security_features.pie),
        12.0,
        Mm(20.0),
        Mm(y_pos),
        &font
    );
    y_pos -= 20.0;

    // NX
    current_layer.use_text(format!("• NX: {:?}", binary.security_features.nx),
        12.0,
        Mm(20.0),
        Mm(y_pos),
        &font
    );
    y_pos -= 20.0;

    // Stack Canary
    current_layer.use_text(format!("• Stack Canary: {:?}", binary.security_features.canary),
        12.0,
        Mm(20.0),
        Mm(y_pos),
        &font
    );
    y_pos -= 20.0;

    // FORTIFY_SOURCE
    current_layer.use_text(format!("• FORTIFY_SOURCE: {:?}", binary.security_features.fortify_source),
        12.0,
        Mm(20.0),
        Mm(y_pos),
        &font
    );
    y_pos -= 20.0;

    // Security Score
    current_layer.use_text(format!("Security Score: {}/10", binary.security_score()),
        14.0,
        Mm(10.0),
        Mm(y_pos),
        &font
    );

    // Save the PDF
    doc.save(&mut BufWriter::new(File::create(output_path)?))?;

    Ok(())
}
