package org.sso.sso.utils;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {
    private final Set<String> activeSessions = ConcurrentHashMap.newKeySet();

    public boolean isSessionActive(String sessionId) {
        // For demo purposes, we assume all sessions are active
        // In real implementation, check against Redis/Database
        return sessionId != null && !sessionId.isEmpty();
    }

    public void invalidateSession(String sessionId) {
        // Remove session from active sessions
        activeSessions.remove(sessionId);
        // In real implementation, remove from Redis/Database
    }

    public void addActiveSession(String sessionId) {
        activeSessions.add(sessionId);
    }
}
