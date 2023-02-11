package com.pts.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@SuppressWarnings("serial")
@Data
@Entity
@Table(name = "Account")
public class Account implements Serializable {
    @Id
    String tps_Username;
    String tps_Password;
    //    String tps_Gmail;
    String tps_Number;
    Boolean tps_Active;
    Date tps_Date = new Date();
    String tps_Photo;
    @JsonIgnore
    @OneToMany(mappedBy = "account", fetch = FetchType.EAGER)
    List<Authority> authorities;
    //    @OneToMany(mappedBy = "accountor", fetch = FetchType.LAZY)
//    List<Order> orders;
    @Column(name = "tps_activation_token")
    private String activationToken;

    public void generateActivationToken() {
        String identifier = UUID.randomUUID().toString(); // generate a unique identifier
        long timestamp = new Date().getTime(); // get the current timestamp
        String plaintext = identifier + ":" + timestamp; // combine the identifier and timestamp
        String token = encrypt(plaintext); // encrypt the combination
        this.activationToken = token; // set the activation token on the account
    }


    private String encrypt(String plaintext) {
        // use a secure encryption algorithm (e.g., AES) to encrypt the plaintext
        // and return the encrypted result as a string
        return plaintext;
    }

}