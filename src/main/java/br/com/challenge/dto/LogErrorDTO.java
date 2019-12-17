package br.com.challenge.dto;

import br.com.challenge.enums.Environment;
import br.com.challenge.enums.ErrorLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LogErrorDTO {

    private String title;

    private String details;

    private Environment environment;

    private ErrorLevel errorLevel;
}
