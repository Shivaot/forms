package com.shivaot.forms.security;

import com.shivaot.forms.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserPrincipal implements UserDetails {

    @Autowired
    private User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        //Extract list of permissions (name)
        this.user.getPermissionsList().forEach(permission -> {
            GrantedAuthority authority = new SimpleGrantedAuthority(permission);
            authorities.add(authority);
        });

        //Extract list of roles (name)
        this.user.getRoleList().forEach(role -> {
            GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);
            authorities.add(authority);
        });

        return authorities;
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
//        return this.user.getActive() == 1;
          return true;
    }

}
