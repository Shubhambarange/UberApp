package com.shubham.project.uber.uberApp.RequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Component
public class AdvancedApiLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AdvancedApiLoggingFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Set max body size to log (to avoid logging huge files)
    private static final int MAX_BODY_SIZE = 10000; // 10KB

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);

        String requestId = UUID.randomUUID().toString();
        long startTime = System.currentTimeMillis();

        try {
            logRequest(requestWrapper, requestId);
            filterChain.doFilter(requestWrapper, responseWrapper);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            logResponse(responseWrapper, requestId, duration);
            responseWrapper.copyBodyToResponse();
        }
    }

    private void logRequest(ContentCachingRequestWrapper request, String requestId) {
        Map<String, Object> logData = new LinkedHashMap<>();

        try {
            logData.put("type", "REQUEST");
            logData.put("requestId", requestId);
            logData.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            logData.put("method", request.getMethod());
            logData.put("uri", request.getRequestURI());
            logData.put("url", request.getRequestURL().toString());

            // Query parameters
            if (request.getQueryString() != null) {
                logData.put("queryString", request.getQueryString());
            }

            // Request parameters
            Map<String, String[]> parameterMap = request.getParameterMap();
            if (!parameterMap.isEmpty()) {
                Map<String, Object> params = new HashMap<>();
                parameterMap.forEach((key, values) -> {
                    if (values.length == 1) {
                        params.put(key, values[0]);
                    } else {
                        params.put(key, Arrays.asList(values));
                    }
                });
                logData.put("parameters", params);
            }

            // Headers
            Map<String, String> headers = new HashMap<>();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                String headerValue = request.getHeader(headerName);

                // Mask sensitive headers
                if (isSensitiveHeader(headerName)) {
                    headerValue = "***MASKED***";
                }
                headers.put(headerName, headerValue);
            }
            logData.put("headers", headers);

            // Client information
            Map<String, String> clientInfo = new HashMap<>();
            clientInfo.put("remoteAddr", request.getRemoteAddr());
            clientInfo.put("remoteHost", request.getRemoteHost());
            clientInfo.put("remotePort", String.valueOf(request.getRemotePort()));
            clientInfo.put("localAddr", request.getLocalAddr());
            clientInfo.put("serverName", request.getServerName());
            clientInfo.put("serverPort", String.valueOf(request.getServerPort()));
            logData.put("client", clientInfo);

            // Request body
            byte[] content = request.getContentAsByteArray();
            if (content.length > 0) {
                String contentType = request.getContentType();
                if (contentType != null && isLoggableContentType(contentType)) {
                    String body = getContentAsString(content, request.getCharacterEncoding());
                    if (body.length() > MAX_BODY_SIZE) {
                        body = body.substring(0, MAX_BODY_SIZE) + "... [TRUNCATED]";
                    }

                    // Try to parse JSON for better formatting
                    if (contentType.contains("application/json")) {
                        try {
                            Object jsonObject = objectMapper.readValue(body, Object.class);
                            logData.put("body", jsonObject);
                        } catch (Exception e) {
                            logData.put("body", body);
                        }
                    } else {
                        logData.put("body", body);
                    }
                } else {
                    logData.put("body", "[Binary content not logged - Content-Type: " + contentType + "]");
                }
            }

            // Session information (if available)
            if (request.getSession(false) != null) {
                logData.put("sessionId", request.getSession().getId());
            }

            // Authentication information (if available)
            if (request.getUserPrincipal() != null) {
                logData.put("authenticatedUser", request.getUserPrincipal().getName());
            }

            logger.info("API_LOG: {}", objectMapper.writeValueAsString(logData));

        } catch (Exception e) {
            logger.error("Error logging request", e);
        }
    }

    private void logResponse(ContentCachingResponseWrapper response, String requestId, long duration) {
        Map<String, Object> logData = new LinkedHashMap<>();

        try {
            logData.put("type", "RESPONSE");
            logData.put("requestId", requestId);
            logData.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            logData.put("status", response.getStatus());
            logData.put("statusText", getStatusText(response.getStatus()));
            logData.put("durationMs", duration);

            // Response headers
            Map<String, String> headers = new HashMap<>();
            Collection<String> headerNames = response.getHeaderNames();
            for (String headerName : headerNames) {
                headers.put(headerName, response.getHeader(headerName));
            }
            logData.put("headers", headers);

            // Response body
            byte[] content = response.getContentAsByteArray();
            if (content.length > 0) {
                String contentType = response.getContentType();
                if (contentType != null && isLoggableContentType(contentType)) {
                    String body = getContentAsString(content, response.getCharacterEncoding());
                    if (body.length() > MAX_BODY_SIZE) {
                        body = body.substring(0, MAX_BODY_SIZE) + "... [TRUNCATED]";
                    }

                    // Try to parse JSON for better formatting
                    if (contentType.contains("application/json")) {
                        try {
                            Object jsonObject = objectMapper.readValue(body, Object.class);
                            logData.put("body", jsonObject);
                        } catch (Exception e) {
                            logData.put("body", body);
                        }
                    } else {
                        logData.put("body", body);
                    }
                } else {
                    logData.put("body", "[Binary content not logged - Content-Type: " + contentType + "]");
                }
            }

            // Add performance warning for slow requests
            if (duration > 5000) {
                logData.put("warning", "SLOW_REQUEST");
            }

            logger.info("API_LOG: {}", objectMapper.writeValueAsString(logData));

        } catch (Exception e) {
            logger.error("Error logging response", e);
        }
    }

    private String getContentAsString(byte[] content, String encoding) {
        try {
            return new String(content, encoding != null ? encoding : "UTF-8");
        } catch (Exception e) {
            return "[Error decoding content]";
        }
    }

    private boolean isSensitiveHeader(String headerName) {
        String lowerCaseName = headerName.toLowerCase();
        return lowerCaseName.contains("authorization") ||
                lowerCaseName.contains("password") ||
                lowerCaseName.contains("token") ||
                lowerCaseName.contains("cookie") ||
                lowerCaseName.contains("secret") ||
                lowerCaseName.contains("api-key") ||
                lowerCaseName.contains("apikey");
    }

    private boolean isLoggableContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        String lowerCaseContentType = contentType.toLowerCase();
        return lowerCaseContentType.contains("json") ||
                lowerCaseContentType.contains("xml") ||
                lowerCaseContentType.contains("text") ||
                lowerCaseContentType.contains("x-www-form-urlencoded");
    }

    private String getStatusText(int status) {
        switch (status) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Status " + status;
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Skip logging for static resources and actuator endpoints
        return path.startsWith("/static") ||
                path.startsWith("/css") ||
                path.startsWith("/js") ||
                path.startsWith("/images") ||
                path.startsWith("/webjars") ||
                path.startsWith("/actuator") ||
                path.endsWith(".css") ||
                path.endsWith(".js") ||
                path.endsWith(".png") ||
                path.endsWith(".jpg") ||
                path.endsWith(".jpeg") ||
                path.endsWith(".gif") ||
                path.endsWith(".svg") ||
                path.endsWith(".ico") ||
                path.endsWith(".woff") ||
                path.endsWith(".woff2") ||
                path.endsWith(".ttf");
    }
}
