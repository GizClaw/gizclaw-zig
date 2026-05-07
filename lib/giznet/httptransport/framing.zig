//! HTTP/1.1 framing helpers for giznet HttpTransport.

const stdz = @import("glib").std;

pub fn responseMustBeBodyless(method: []const u8, status_code: u16) bool {
    if (status_code >= 100 and status_code < 200) return true;
    if (status_code == 204 or status_code == 304) return true;
    return stdz.ascii.eqlIgnoreCase(method, "HEAD");
}

pub fn isInformationalResponse(status_code: u16) bool {
    return status_code >= 100 and status_code < 200;
}

pub fn countHeaderLines(header_block: []const u8) usize {
    var count: usize = 0;
    var line_start: usize = 0;
    while (line_start < header_block.len) {
        const rel_end = stdz.mem.indexOf(u8, header_block[line_start..], "\r\n") orelse break;
        if (rel_end == 0) break;
        count += 1;
        line_start += rel_end + 2;
    }
    return count;
}

pub fn containsToken(value: []const u8, token: []const u8) bool {
    var start: usize = 0;
    while (start <= value.len) {
        const comma = stdz.mem.indexOfScalar(u8, value[start..], ',') orelse value.len - start;
        const part = stdz.mem.trim(u8, value[start .. start + comma], " \t");
        if (stdz.ascii.eqlIgnoreCase(part, token)) return true;
        if (start + comma >= value.len) break;
        start += comma + 1;
    }
    return false;
}
