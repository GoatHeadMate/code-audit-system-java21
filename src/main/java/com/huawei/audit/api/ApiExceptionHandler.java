package com.huawei.audit.api;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, Object>> statusException(
            ResponseStatusException exception,
            HttpServletRequest request
    ) {
        return response(
                exception.getStatusCode().value(),
                exception.getReason(),
                request
        );
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<Map<String, Object>> uploadTooLarge(
            MaxUploadSizeExceededException exception,
            HttpServletRequest request
    ) {
        return response(
                HttpStatus.PAYLOAD_TOO_LARGE.value(),
                "uploaded ZIP exceeds the configured size limit",
                request
        );
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, Object>> unexpected(
            Exception exception,
            HttpServletRequest request
    ) {
        int status = exception instanceof ErrorResponse errorResponse
                ? errorResponse.getStatusCode().value()
                : HttpStatus.INTERNAL_SERVER_ERROR.value();
        String detail = exception.getMessage();
        if (detail == null || detail.isBlank()) {
            detail = HttpStatus.valueOf(status).getReasonPhrase();
        }
        return response(status, detail, request);
    }

    private ResponseEntity<Map<String, Object>> response(
            int status,
            String detail,
            HttpServletRequest request
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("detail", detail == null ? "request failed" : detail);
        body.put("path", request.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }
}
