package br.com.challenge.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class CredentialsDTO implements Serializable {
    private static final long serialVersionUID = 1l;

    private String email;
    private String password;
}
