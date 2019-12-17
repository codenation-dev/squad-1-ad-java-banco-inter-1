package br.com.challenge.entity;

import br.com.challenge.enums.Profile;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.lang.Nullable;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
@Data
@Entity
public class Users {

    @Transient
    @JsonIgnore
    private String uri;

    @Id
    @GeneratedValue(generator = "increment")
    @GenericGenerator(name = "increment", strategy = "increment")
    private Long id;

    @Column(unique = true)
    private String token;

    @Column(length = 80)
    @NotNull
    private String name;

    @Column(length = 80)
    @Nullable
    private String adress;

    @Column(length = 10)
    @Nullable
    private String number;

    @Column(length = 80)
    @Nullable
    private String neighborhood;

    @Column(length = 80)
    @Nullable
    private String city;

    @Column(length = 100, unique = true)
    @Email
    @NotNull
    private String email;

    @Column(length = 80)
    @NotNull
    private String password;

    private boolean active;

    @JsonIgnore
    @OneToMany(mappedBy="users", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<LogError> logErrorList;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "Profile")
    private Set<Integer> profiles = new HashSet<>();

    public Users() {
        this.active = false;
        addProfile(Profile.USER);
    }

    public Set<Profile> getProfiles() {
        return profiles.stream().map(x -> Profile.toEnum(x)).collect(Collectors.toSet());
    }

    public void addProfile(Profile profile) {
        profiles.add(profile.getCod());
    }

    @Override
    public String toString() {

//        String adressString = adress == null ?  "" : adress;
//        String numberString = number == null ?  "" : number;
//        String neighborhoodString = neighborhood == null ?  "" : neighborhood;
//        String cityString = city == null ?  "" : city;

        return " Olá! ".concat(name).concat("\n").concat("\n")
                .concat("Obrigado por se registrar em nossa central de erros").concat("\n")
                .concat("Segue suas informações de registro.").concat("\n").concat("\n")
                .concat("Name: ").concat(name).concat("\n")
//                .concat("Adress: ").concat(adressString).concat("\n")
//                .concat("Number: ").concat(numberString).concat("\n")
//                .concat("Neighborhood: ").concat(neighborhoodString).concat("\n")
//                .concat("City: ").concat(cityString).concat("\n")
                .concat("Email: ").concat(email).concat("\n")
                .concat("Password: ").concat("*********").concat("\n")
                .concat("Profile: ").concat(profiles.toString()).concat("\n").concat("\n").concat("\n")
                .concat("Clique no link abaixo para confirmar sua conta e concluir seu registro.").concat("\n").concat("\n")
                .concat(uri);
    }
}