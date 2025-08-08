package com.yia0507.boot_edu_jwt_250806.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class APIUser {
    @Id
    private String mid;
    private String mpw;

    public void changePw(String mpw) {
        this.mpw = mpw;
    }
}
