package com.softserveinc.ch067.easypay.util;

import com.google.api.services.drive.model.File;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.softserveinc.ch067.easypay.dto.CounterDTO;
import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import com.softserveinc.ch067.easypay.service.IGoogleDriveService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.stream.Stream;

@Component
public class HistoryPDFBuilder {
    @Autowired
    private IGoogleDriveService driveService;

    private Font headerFont;
    private Font dataFont;

    private final int tableColumnsNumber = 2;

    public GeneratedFileDTO createCheck(PaymentsHistoryPDFDetails details, PaymentsHistory paymentsHistory) throws Exception{
        byte[] fileContent = new byte[1];
        File file = null;

        BaseFont headerBaseFont = BaseFont.createFont(FontFactory.COURIER_BOLD, "UTF-8", BaseFont.EMBEDDED);

        String path = getClass().getResource("/fonts/cour.ttf").getFile();
        path = path.replaceAll("%20", " ");     // Replacing all the SPACES (%20) in URL to

        BaseFont dataBaseFont = BaseFont.createFont(path, "CP1251", BaseFont.EMBEDDED);

        headerFont = new Font(headerBaseFont, 12);
        dataFont = new Font(dataBaseFont, 12);

        Document document = new Document(PageSize.A4);

        OutputStream outputStream = new ByteArrayOutputStream();

        PdfWriter.getInstance(document, outputStream);

        document.open();

        PdfPTable table = new PdfPTable(tableColumnsNumber);

        Font nameFont = new Font(headerFont);
        nameFont.setSize(16);

        Paragraph personNameParagraph = new Paragraph(details.getUserName() + "'s check", nameFont);
        Paragraph paymentServiceParagraph = new Paragraph("Utility: " + details.getServiceName(), dataFont);
        Paragraph paymentAddressParagraph = new Paragraph(details.getAddress(), dataFont);
        Paragraph countersParagraph = new Paragraph("Counters values at the moment of the payment: ", dataFont);
        Paragraph priceParagraph = new Paragraph("Price: " + details.getRate(), dataFont);

        document.add(personNameParagraph);
        document.add(paymentAddressParagraph);
        document.add(paymentServiceParagraph);
        document.add(priceParagraph);
        document.add(countersParagraph);

        table.setWidthPercentage(100);
        table.setWidths(new int[]{6, 4});     // Specifying a width of each table's column.
        addTableHeader(table);
        addRows(table, details);

        table.setSpacingBefore(10);
        table.setSpacingAfter(20);
        document.add(table);

        double totalSum = 0;    // This variable stores the total amount of money paid.

        Paragraph totalSumParagraph = new Paragraph("Total sum: " + totalSum, dataFont);
        totalSumParagraph.setAlignment(Element.ALIGN_RIGHT);

        Paragraph oldDebtParagraph = new Paragraph("Utility balance before the payment: " + -details.getOldDebt() + " UAH.", dataFont);
        Paragraph newDebtParagraph = new Paragraph("Utility balance after the payment: " + -details.getNewDebt() + " UAH.", dataFont);
        Paragraph paidSumParagraph = new Paragraph(new Chunk("Paid: ", headerFont) + String.valueOf(Math.abs(details.getOldDebt() - details.getNewDebt())) + " UAH.", dataFont);
        Paragraph paymentTimeParagraph = new Paragraph(String.valueOf(details.getPaymentTime()), dataFont);

        document.add(oldDebtParagraph);
        document.add(newDebtParagraph);
        document.add(paidSumParagraph);
        document.add(paymentTimeParagraph);
        document.close();
        outputStream.close();
        fileContent = ((ByteArrayOutputStream) outputStream).toByteArray();

        file = driveService.createPDFFile(fileContent, details.getUserEmail(), details.getFileName());
        paymentsHistory.setGoogleDriveFileId(file.getId());

        return new GeneratedFileDTO(file.getId(), details.getFileName(), fileContent);
    }

    /*
     *    This method is responsible for adding a HEADER to the table.
     *    If you want to add a new header column, you have to add it into Stream.of() method.
     *    For each of these header columns, there is an algorithm that adds them.
    */
    public void addTableHeader(PdfPTable table) {
        Stream.of("Prev. counter value", "Counter value")
                .forEach(columnTitle -> {
                    PdfPCell header = new PdfPCell();
                    header.setBackgroundColor(BaseColor.LIGHT_GRAY);    // Specifying header column's background color.
                    header.setBorderWidth(1);   // Specifying border width of header column.
                    header.setPhrase(new Phrase(columnTitle, headerFont));      // Specifying the text (phrase) of header column.
                    header.setHorizontalAlignment(Element.ALIGN_CENTER);    // Specifying the alignment of the text (phrase) of header column.
                    table.addCell(header);      // Finally, attaching a header to the table.
                });
    }

    // This method's destination is to fill in data columns of the table. This data is Payments History details.
    public void addRows(PdfPTable table, PaymentsHistoryPDFDetails details) {
        for (CounterDTO c : details.getCounters()){
            table.addCell(String.valueOf(c.getOldValue()));
            table.addCell(String.valueOf(c.getCurrentValue()));
        }
    }
}
