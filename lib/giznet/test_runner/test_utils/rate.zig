const glib = @import("glib");

pub fn bytesPerSecond(bytes: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0 or bytes == 0) return 0;
    return mulDivU64(bytes, @intCast(glib.time.duration.Second), elapsed_ns);
}

pub fn opsPerSecond(iterations: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0 or iterations == 0) return 0;
    return mulDivU64(iterations, @intCast(glib.time.duration.Second), elapsed_ns);
}

pub fn mbps(bytes_per_second: u64) u64 {
    return mulDivU64(bytes_per_second, 8, 1_000_000);
}

pub fn mulDivU64(a: u64, b: u64, divisor: u64) u64 {
    if (a == 0 or b == 0) return 0;
    if (divisor == 0) return max_u64;

    var lhs = a;
    var rhs = b;
    var denominator = divisor;

    const lhs_gcd = gcdU64(lhs, denominator);
    lhs /= lhs_gcd;
    denominator /= lhs_gcd;

    const rhs_gcd = gcdU64(rhs, denominator);
    rhs /= rhs_gcd;
    denominator /= rhs_gcd;

    const product = mulSaturatingU64(lhs, rhs);
    return @divTrunc(product, denominator);
}

pub fn mulSaturatingU64(a: u64, b: u64) u64 {
    const result, const overflowed = @mulWithOverflow(a, b);
    return if (overflowed != 0) max_u64 else result;
}

pub fn addSaturatingU64(a: u64, b: u64) u64 {
    const result, const overflowed = @addWithOverflow(a, b);
    return if (overflowed != 0) max_u64 else result;
}

fn gcdU64(a: u64, b: u64) u64 {
    var lhs = a;
    var rhs = b;
    while (rhs != 0) {
        const next = lhs % rhs;
        lhs = rhs;
        rhs = next;
    }
    return lhs;
}

const max_u64: u64 = 18_446_744_073_709_551_615;
