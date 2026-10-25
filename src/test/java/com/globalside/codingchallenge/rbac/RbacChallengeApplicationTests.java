package com.globalside.codingchallenge.rbac;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.globalside.codingchallenge.rbac.constants.SecuriryConstants;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional                  // @Transactional rolled back after the test finishes, preventing test changes from persisting in the database.
class RbacChallengeApplicationTests {

    private static final String badCredintails = "Basic dXNlcjpiYWRwYXNzd29yZA==";   // The Base64 value dXNlcjpiYWRwYXNzd29yZA== decodes to user:badpassword.
    private static final String urlToProducts = "/products";
    private static final String urlToProduct3 =  urlToProducts + "/3";
    private static final String testProduct = """
        {
            "name": "T-Shirt",
            "description": "Very nice product with discount.",
            "price": 5.49,
            "currency": "EUR",
            "category": "CLOTHING",
            "brand": "NONAME",
            "color": "white"                
        }""";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads() {
    }

    // ******************************** Test admin credintails: *************************************************

    @Test
    @WithMockUser(roles = SecuriryConstants.ADMIN_ROLE)
    void adminCanViewProducts() throws Exception {
        mockMvc.perform(get(urlToProducts)).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.ADMIN_ROLE)
    void adminCanViewProduct() throws Exception {
        mockMvc.perform(get(urlToProduct3)).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.ADMIN_ROLE)
    void adminCanCreateProduct() throws Exception {
        mockMvc.perform(post(urlToProducts)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.ADMIN_ROLE)
    void adminCanUpdateProduct() throws Exception {
        mockMvc.perform(put(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.ADMIN_ROLE)
    void adminDeleteProduct() throws Exception {
        mockMvc.perform(delete(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(""))
            .andExpect(status().isOk());
    }


    // ******************************** Test user credintails: *************************************************

    @Test
    @WithMockUser(roles = SecuriryConstants.USER_ROLE)
    void userCanViewProducts() throws Exception {
        mockMvc.perform(get(urlToProducts)).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.USER_ROLE)
    void userCanViewProduct() throws Exception {
        mockMvc.perform(get(urlToProduct3)).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.USER_ROLE)
    void userCannotCreateProduct() throws Exception {
        mockMvc.perform(post(urlToProducts)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.USER_ROLE)
    void userCannotUpdateProduct() throws Exception {
        mockMvc.perform(put(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = SecuriryConstants.USER_ROLE)
    void userCannotDeleteProduct() throws Exception {
        mockMvc.perform(delete(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(""))
            .andExpect(status().isForbidden());
    }


    // ******************************** Test unauthenticated user credintails: *************************************************

    @Test
    void unauthenticatedUserCannotViewProducts() throws Exception {
        mockMvc.perform(get(urlToProducts)).andExpect(status().isForbidden());
    }    

    @Test
    void unauthenticatedUserCannotViewProduct() throws Exception {
        mockMvc.perform(get(urlToProduct3)).andExpect(status().isForbidden());
    }    

    @Test
    void unauthenticatedUserCannotCreateProduct() throws Exception {
        mockMvc.perform(post(urlToProducts)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedUserCannotUpdateProduct() throws Exception {
        mockMvc.perform(put(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(testProduct))
            .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedUserCannotDeleteProduct() throws Exception {
        mockMvc.perform(delete(urlToProduct3)
            .contentType(MediaType.APPLICATION_JSON)
            .content(""))
            .andExpect(status().isForbidden());
    }

    // ******************************** Test invalid credintails: *************************************************

    @Test
    void incorrectCredentialsViewProductsReturn403() throws Exception {
    mockMvc.perform(get(urlToProducts)
            .header(HttpHeaders.AUTHORIZATION, badCredintails))
            .andExpect(status().isForbidden());
    }

    @Test
    void incorrectCredentialsViewProductReturn403() throws Exception {
    mockMvc.perform(get(urlToProduct3)
            .header(HttpHeaders.AUTHORIZATION, badCredintails))
            .andExpect(status().isForbidden());
    }

    @Test
    void incorrectCredentialsCreateProductReturn403() throws Exception {
    mockMvc.perform(post(urlToProducts)
            .header(HttpHeaders.AUTHORIZATION, badCredintails))
            .andExpect(status().isForbidden());
    }

    @Test
    void incorrectCredentialsUpdateProductReturn403() throws Exception {
    mockMvc.perform(put(urlToProduct3)
            .header(HttpHeaders.AUTHORIZATION, badCredintails))
            .andExpect(status().isForbidden());
    }

    @Test
    void incorrectCredentialsDeleteProductReturn403() throws Exception {
    mockMvc.perform(delete(urlToProduct3)
            .header(HttpHeaders.AUTHORIZATION, badCredintails))
            .andExpect(status().isForbidden());
    }
}