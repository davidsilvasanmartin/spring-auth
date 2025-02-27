package dev.davidsilva.auth.session.api.hello;

import dev.davidsilva.auth.session.api.config.TestConfig;
import dev.davidsilva.auth.session.api.security.user.User;
import dev.davidsilva.auth.session.api.security.user.UserRepository;
import org.springframework.context.annotation.Import;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestConfig.class)
class HelloControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        User user = User.builder()
                .username("testuser")
                .password("password")
                .authorities(Set.of("USER"))
                .build();

        User admin = User.builder()
                .username("testadmin")
                .password("password")
                .authorities(Set.of("ADMIN"))
                .build();

        userRepository.saveAll(Set.of(user, admin));
    }

    @Test
    void whenUnauthenticated_thenUnauthorized() throws Exception {
        mockMvc.perform(get("/hello").with(csrf()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/admin").with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "USER")
    void whenUserAccess_thenCorrect() throws Exception {
        mockMvc.perform(get("/hello").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("testuser"));

        mockMvc.perform(get("/admin").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "testadmin", authorities = "ADMIN")
    void whenAdminAccess_thenCorrect() throws Exception {
        mockMvc.perform(get("/hello").with(csrf()))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/admin").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("testadmin"));
    }

    @Test
    void whenNoCsrf_thenForbidden() throws Exception {
        mockMvc.perform(get("/hello"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "USER")
    void whenValidSession_thenSuccess() throws Exception {
        MvcResult result = mockMvc.perform(get("/hello").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("JSESSIONID"))
                .andReturn();

        String sessionId = result.getResponse().getCookie("JSESSIONID").getValue();

        // Subsequent request with same session should work
        mockMvc.perform(get("/hello")
                        .with(csrf())
                        .sessionAttr("JSESSIONID", sessionId))
                .andExpect(status().isOk());
    }
}
