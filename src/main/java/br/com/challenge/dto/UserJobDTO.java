package br.com.challenge.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserJobDTO {
    private String name;

    private String email;

    private String token;

    private boolean active;

    private boolean notified;
}
