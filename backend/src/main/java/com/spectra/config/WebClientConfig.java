package com.spectra.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class WebClientConfig {

    @Value("${spectra.flask.url}")
    private String flaskUrl;

    @Value("${spectra.flask.api-key}")
    private String flaskApiKey;

    @Bean
    public WebClient flaskWebClient() {
        // Configure HTTP client with longer timeouts for large evidence processing
        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 300000) // 5 minutes
                .responseTimeout(Duration.ofMinutes(5))
                .doOnConnected(conn -> 
                    conn.addHandlerLast(new ReadTimeoutHandler(300, TimeUnit.SECONDS))
                        .addHandlerLast(new WriteTimeoutHandler(300, TimeUnit.SECONDS)));

        return WebClient.builder()
                .baseUrl(flaskUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .defaultHeader("X-API-Key", flaskApiKey)
                .defaultHeader("Content-Type", "application/json")
                .codecs(c -> c.defaultCodecs().maxInMemorySize(50 * 1024 * 1024)) // 50MB for large responses
                .build();
    }
}
