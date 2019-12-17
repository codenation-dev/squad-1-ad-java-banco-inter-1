package br.com.challenge.entity;

import br.com.challenge.enums.Environment;
import br.com.challenge.enums.ErrorLevel;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "LogError")
public class LogError {

    @Id
    @GeneratedValue(generator = "increment")
    @GenericGenerator(name = "increment", strategy = "increment")
    private Long id;

    @ManyToOne
    @JoinColumn(name="users_id", nullable=false)
    private Users users;

    @NotNull
    private Environment environment;

    @Column(length = 100)
    @NotNull
    private String requestIp;

    @NotNull
    private ErrorLevel level;

    @Column(length = 100)
    @NotNull
    private String title;

    @NotNull
    private String details;

    @Column
    private boolean filed;

    @Column
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    private LocalDateTime createdAt;
}
