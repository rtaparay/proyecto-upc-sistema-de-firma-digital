package models;

import play.db.jpa.GenericModel;

import javax.persistence.*;
import java.util.Date;

@Entity
public class Subscriber extends GenericModel {

    @Id
    public String email;

    public String emailVerificationCode;

    public boolean emailVerified;

    public String password;

    public String fullName;

    public String dni;

    @Lob
    public String dniFile;
    @Lob
    public String fichaRucFile;
    @Lob
    public String powerOfAttorneyFile;

    @Lob
    public String signatureSvg;
    
    public boolean dniFileValidated;
    public boolean fichaRucFileValidated;
    public boolean powerOfAttorneyFileValidated;
    public String ruc;
    public String companyName;

    @Lob
    public String certificateP12;
    
    @Lob
    public String certificatePem;
    public String validatedBy;
    public Date validatedAt;
}
