#pragma once

#include <cstdint>

enum class Commands : int
{
    // ============================================================
    // 1 - 9 : Session / Lifecycle
    // ============================================================

    SESSION_INIT = 1,       // Initiates a new logical session between Bridge and Gate
    SESSION_CONFIRM = 2,    // Confirms that the session has been successfully established
    SESSION_CLOSE = 3,      // Requests graceful termination of an active session
    SESSION_TERMINATED = 4, // Indicates that the session has been fully terminated

    // ============================================================
    // 10-29 : Health & Metrics
    // ============================================================

    HEALTH_REPORT = 10,    // Sends a full health snapshot
    HEALTH_UPDATE = 11,    // Sends incremental health updates
    HEALTH_DEGRADED = 12,  // Node performance dropped below threshold
    HEALTH_RECOVERED = 13, // Node recovered to acceptable state

    LOAD_REPORT = 14,   // Sends current load metrics
    LOAD_SPIKE = 15,    // Sudden abnormal traffic spike detected
    LOAD_NORMAL = 16,   // System returned to normal load
    LOAD_CRITICAL = 17, // System is under critical load

    CONGESTION_REPORT = 18, // Reports congestion metrics
    CONGESTION_HIGH = 19,   // High congestion state
    CONGESTION_MEDIUM = 20, // Medium congestion state
    CONGESTION_LOW = 21,    // Low congestion state

    // ============================================================
    // 30 - 39 : Flow & Traffic Control
    // ============================================================

    FLOW_PAUSE = 30,     // Temporarily pauses traffic forwarding
    FLOW_RESUME = 31,    // Resumes paused traffic
    FLOW_TERMINATE = 32, // Immediately terminates active flow

    THROTTLE_ENABLE = 33,   // Enables throttling mechanism
    THROTTLE_DISABLE = 34,  // Disables throttling
    RATE_LIMIT_UPDATE = 35, // Updates rate limiting parameters

    // ============================================================
    // 40-49 : Security / Authorization
    // ============================================================

    PERMISSION_DENIED = 40, // Requested operation is not authorized

    // ============================================================
    // 50-59 : Generic Responses
    // ============================================================

    RESPONSE_OK = 50,       // Operation completed successfully
    RESPONSE_ERROR = 51,    // Operation failed (generic error)
    RESPONSE_INVALID = 52,  // Invalid or malformed request

    // ============================================================
    // 60-79 : HTTP / Payload Transfer
    // ============================================================

    HTTP_REQUEST = 60,  // Carries raw HTTP request payload
    HTTP_RESPONSE = 61, // Carries raw HTTP response payload
};
