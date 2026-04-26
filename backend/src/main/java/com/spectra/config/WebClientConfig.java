package com.spectra.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Value("${spectra.flask.url}")
    private String flaskUrl;

    @Value("${spectra.flask.api-key}")
    private String flaskApiKey;

    @Bean
    public WebClient flaskWebClient() {
        return WebClient.builder()
                .baseUrl(flaskUrl)
                .defaultHeader("X-API-Key", flaskApiKey)
                .defaultHeader("Content-Type", "application/json")
                .codecs(c -> c.defaultCodecs().maxInMemorySize(10 * 1024 * 1024))
                .build();
    }
}
