package models;

import play.data.validation.Required;
import play.db.jpa.GenericModel;

import javax.persistence.*;

@Entity
public class PdfDocument extends GenericModel {

    @Id
    @Required
    @GeneratedValue()
    public int id;

    @ManyToOne
    @JoinColumn(name = "subscriber")
    public Subscriber subscriber;

    @Lob
    public String pdfContent;

    @Lob
    public String signedPdfContent;
    
    public String pdfName;
}
