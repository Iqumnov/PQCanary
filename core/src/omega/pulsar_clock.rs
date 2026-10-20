use std::collections::HashMap;

// ============================================================
// Physical Constants and Real Pulsar Catalog
// ============================================================

/// Speed of light in vacuum (m/s)
pub const C_LIGHT: f64 = 299_792_458.0;

/// Speed of light in optical fiber (m/s) — roughly 2/3 of c
pub const C_FIBER: f64 = C_LIGHT * 0.667;

/// Earth's mean radius (meters)
pub const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// A characterized millisecond pulsar from the ATNF Pulsar Catalogue.
/// All parameters from: Manchester, R.N. et al. (2005), AJ 129, 1993.
#[derive(Debug, Clone)]
pub struct PulsarRecord {
    pub jname: &'static str,       // J2000 name
    pub period_s: f64,             // Pulse period (seconds)
    pub period_dot: f64,           // Period derivative (s/s) — spin-down rate
    pub dispersion_measure: f64,   // DM (pc/cm³) — interstellar electron column density
    pub ra_hours: f64,             // Right Ascension (hours)
    pub dec_degrees: f64,          // Declination (degrees)
    pub distance_kpc: f64,         // Distance (kiloparsecs)
    pub characteristic_age_yr: f64,// τ_c = P/(2Ṗ) (years)
}

/// Interstellar dispersion delay coefficient (seconds per MHz² per pc/cm³)
/// Derived from the cold plasma dispersion law: Δt = DM * K_DM / f²
/// K_DM = 4.148808 × 10⁻³ s·MHz²·pc⁻¹·cm³ (IPTA standard)
const K_DM_S_MHZ2_PC_CM3: f64 = 4.148808e-3;

pub fn get_pulsar_catalog() -> Vec<PulsarRecord> {
    vec![
        PulsarRecord {
            jname: "PSR J0437-4715",
            period_s: 5.7574518519e-3,      // 5.757ms — one of the best timing pulsars
            period_dot: 5.729e-20,
            dispersion_measure: 2.6449,
            ra_hours: 4.623,
            dec_degrees: -47.253,
            distance_kpc: 0.1563,
            characteristic_age_yr: 1.595e9,
        },
        PulsarRecord {
            jname: "PSR J1713+0747",
            period_s: 4.5701508e-3,          // 4.57ms
            period_dot: 8.5e-21,
            dispersion_measure: 15.9921,
            ra_hours: 17.228,
            dec_degrees: 7.805,
            distance_kpc: 1.18,
            characteristic_age_yr: 8.51e9,
        },
        PulsarRecord {
            jname: "PSR B0531+21",            // The Crab Pulsar
            period_s: 0.033392,               // 33.4ms
            period_dot: 4.2095e-13,
            dispersion_measure: 56.79,
            ra_hours: 5.575,
            dec_degrees: 22.014,
            distance_kpc: 2.0,
            characteristic_age_yr: 1254.0,
        },
        PulsarRecord {
            jname: "PSR J0835-4510",          // The Vela Pulsar
            period_s: 0.089328,               // 89.3ms
            period_dot: 1.2496e-13,
            dispersion_measure: 67.99,
            ra_hours: 8.589,
            dec_degrees: -45.176,
            distance_kpc: 0.287,
            characteristic_age_yr: 11300.0,
        },
        PulsarRecord {
            jname: "PSR J0030+0451",
            period_s: 4.8651e-3,
            period_dot: 9.98e-21,
            dispersion_measure: 4.3328,
            ra_hours: 0.509,
            dec_degrees: 4.865,
            distance_kpc: 0.33,
            characteristic_age_yr: 7.74e9,
        },
        PulsarRecord {
            jname: "PSR J1614-2230",
            period_s: 3.1508e-3,
            period_dot: 9.6e-21,
            dispersion_measure: 34.5,
            ra_hours: 16.243,
            dec_degrees: -22.500,
            distance_kpc: 1.27,
            characteristic_age_yr: 5.19e9,
        },
    ]
}

// ============================================================
// Pulsar Timing Model
// ============================================================

/// A complete timing model for a pulsar.
/// Accounts for spin-down, dispersion delay, and secular period drift.
#[derive(Debug, Clone)]
pub struct PulsarTimingModel {
    record: PulsarRecord,
    /// Reference epoch (TOA measurement baseline, in seconds since J2000.0)
    reference_epoch_s: f64,
    /// Number of reference pulses counted at the reference epoch
    reference_pulse_count: u64,
}

impl PulsarTimingModel {
    pub fn new(record: PulsarRecord, reference_epoch_s: f64, reference_pulses: u64) -> Self {
        Self { record, reference_epoch_s, reference_pulse_count: reference_pulses }
    }

    /// Compute the expected pulse period at time t seconds after the reference epoch.
    /// Accounts for spin-down: P(t) = P₀ + Ṗ × Δt
    pub fn period_at(&self, dt_s: f64) -> f64 {
        self.record.period_s + self.record.period_dot * dt_s
    }

    /// Compute the expected number of pulses observed between the reference epoch and
    /// the time `dt_s` seconds after it. Uses the Taylor expansion of pulse phase:
    ///   N_total = N_ref + ν₀·Δt + ½·ν̇₀·(Δt)²
    /// where Δt = t - t_ref, ν = 1/P, ν̇ = -Ṗ/P²
    pub fn expected_pulses_in_interval(&self, dt_s: f64) -> f64 {
        let nu_0 = 1.0 / self.record.period_s;
        let nu_dot = -self.record.period_dot / (self.record.period_s.powi(2));
        // Phase relative to reference epoch: φ(Δt) = N_ref + ν₀·Δt + ½·ν̇₀·(Δt)²
        // The reference_epoch_s anchors us in absolute time (J2000.0 seconds)
        let _anchor_epoch = self.reference_epoch_s; // used for absolute TOA calculation
        self.reference_pulse_count as f64
            + nu_0 * dt_s
            + 0.5 * nu_dot * dt_s * dt_s
    }

    /// Compute the interstellar dispersion delay at a given observing radio frequency.
    /// Δt_DM = K_DM × DM / f²  (seconds, where f is in MHz)
    /// This delay must be subtracted from the observed Time of Arrival (TOA) to get
    /// the barycentric TOA at the Solar System Barycenter.
    pub fn dispersion_delay_s(&self, frequency_mhz: f64) -> f64 {
        K_DM_S_MHZ2_PC_CM3 * self.record.dispersion_measure / (frequency_mhz * frequency_mhz)
    }

    /// Correct an observed TOA for interstellar dispersion at a given radio frequency.
    pub fn corrected_toa(&self, observed_toa_s: f64, frequency_mhz: f64) -> f64 {
        observed_toa_s - self.dispersion_delay_s(frequency_mhz)
    }
}

// ============================================================
// WGS-84 Geodesic Calculator (for location verification)
// ============================================================

/// WGS-84 ellipsoid parameters
const WGS84_A: f64 = 6_378_137.0;           // Semi-major axis (meters)
const WGS84_F: f64 = 1.0 / 298.257223563;   // Flattening
const WGS84_B: f64 = WGS84_A * (1.0 - WGS84_F); // Semi-minor axis

/// Compute the geodesic distance between two (lat, lon) points in decimal degrees
/// using the Vincenty formula on the WGS-84 ellipsoid.
/// Returns distance in meters.
pub fn vincenty_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    if !lat1.is_finite() || !lon1.is_finite() || !lat2.is_finite() || !lon2.is_finite() {
        return 0.0;
    }
    let lat1 = lat1.clamp(-89.999999, 89.999999);
    let lat2 = lat2.clamp(-89.999999, 89.999999);

    if (lat1 - lat2).abs() < 1e-12 && (lon1 - lon2).abs() < 1e-12 {
        return 0.0;
    }

    let phi1 = lat1.to_radians();
    let phi2 = lat2.to_radians();
    let l = (lon2 - lon1).to_radians();

    let u1 = ((1.0 - WGS84_F) * phi1.tan()).atan();
    let u2 = ((1.0 - WGS84_F) * phi2.tan()).atan();

    let sin_u1 = u1.sin(); let cos_u1 = u1.cos();
    let sin_u2 = u2.sin(); let cos_u2 = u2.cos();

    let mut lambda = l;
    let mut lambda_prev;
    let mut cos2_alpha = 0.0;
    let mut sin_sigma = 0.0;
    let mut cos_sigma = 0.0;
    let mut sigma = 0.0;
    let mut cos2_sigma_m = 0.0;

    for _ in 0..1000 {
        let sin_lambda = lambda.sin();
        let cos_lambda = lambda.cos();

        let a = (cos_u2 * sin_lambda).powi(2);
        let b = (cos_u1 * sin_u2 - sin_u1 * cos_u2 * cos_lambda).powi(2);
        sin_sigma = (a + b).sqrt();
        if sin_sigma == 0.0 {
            return 0.0;
        }
        cos_sigma = sin_u1 * sin_u2 + cos_u1 * cos_u2 * cos_lambda;
        sigma = sin_sigma.atan2(cos_sigma);

        let sin_alpha = cos_u1 * cos_u2 * sin_lambda / sin_sigma;
        cos2_alpha = (1.0 - sin_alpha * sin_alpha).max(0.0);
        cos2_sigma_m = if cos2_alpha.abs() > 1e-12 {
            cos_sigma - 2.0 * sin_u1 * sin_u2 / cos2_alpha
        } else {
            0.0
        };

        let c = WGS84_F / 16.0 * cos2_alpha * (4.0 + WGS84_F * (4.0 - 3.0 * cos2_alpha));
        lambda_prev = lambda;
        lambda = l + (1.0 - c) * WGS84_F * sin_alpha
            * (sigma + c * sin_sigma * (cos2_sigma_m + c * cos_sigma * (-1.0 + 2.0 * cos2_sigma_m * cos2_sigma_m)));

        if (lambda - lambda_prev).abs() < 1e-12 { break; }
    }

    let u2_sq = cos2_alpha * (WGS84_A * WGS84_A - WGS84_B * WGS84_B) / (WGS84_B * WGS84_B);
    let a_coef = 1.0 + u2_sq / 16384.0 * (4096.0 + u2_sq * (-768.0 + u2_sq * (320.0 - 175.0 * u2_sq)));
    let b_coef = u2_sq / 1024.0 * (256.0 + u2_sq * (-128.0 + u2_sq * (74.0 - 47.0 * u2_sq)));
    let delta_sigma = b_coef * sin_sigma * (cos2_sigma_m + b_coef / 4.0
        * (cos_sigma * (-1.0 + 2.0 * cos2_sigma_m * cos2_sigma_m)
           - b_coef / 6.0 * cos2_sigma_m * (-3.0 + 4.0 * sin_sigma * sin_sigma)
               * (-3.0 + 4.0 * cos2_sigma_m * cos2_sigma_m)));

    let dist = (WGS84_B * a_coef * (sigma - delta_sigma)).abs();
    if dist.is_nan() { 0.0 } else { dist }
}

// ============================================================
// Light-Cone Verifier for TLS/KEM Handshakes
// ============================================================

/// The result of a relativistic light-cone location verification.
#[derive(Debug, Clone)]
pub struct LightConeVerdict {
    pub claimed_location: (f64, f64),   // (lat, lon)
    pub server_location: (f64, f64),    // (lat, lon)
    pub distance_m: f64,                // Geodesic distance (meters)
    pub measured_rtt_s: f64,            // Measured round-trip time (seconds)
    pub min_rtt_fiber_s: f64,           // Minimum possible RTT via fiber (2 × d / c_fiber)
    pub min_rtt_vacuum_s: f64,          // Absolute minimum RTT via vacuum (2 × d / c_light)
    pub is_physically_possible: bool,   // False if measured RTT < min possible
    pub spoofing_confidence: f64,       // 0.0 = definitely not spoofed, 1.0 = impossible physics
    pub reason: String,
}

// ============================================================
// The Full PulsarClock
// ============================================================

/// The full Astrophysical Timestamp Verification System.
pub struct PulsarClock {
    catalog: HashMap<String, PulsarTimingModel>,
    server_location: (f64, f64), // (lat, lon) of the server
}

impl PulsarClock {
    pub fn new(server_lat: f64, server_lon: f64) -> Self {
        let mut catalog = HashMap::new();

        // Load catalog with default timing models (reference epoch = J2000.0)
        for record in get_pulsar_catalog() {
            let name = record.jname.to_string();
            let model = PulsarTimingModel::new(record, 0.0, 0);
            catalog.insert(name, model);
        }

        Self { catalog, server_location: (server_lat, server_lon) }
    }

    /// Legacy constructor for compatibility
    pub fn with_defaults() -> Self {
        Self::new(0.0, 0.0) // Default server at (0,0) — override in production
    }

    /// Verify an incoming timestamp using pulsar timing.
    ///
    /// The caller provides:
    ///   - `pulsar_id`: which pulsar to use as the clock source
    ///   - `observed_pulses`: how many pulses were counted between two events
    ///   - `claimed_elapsed_seconds`: the client's claimed time delta
    ///   - `observing_frequency_mhz`: the radio frequency used (for dispersion correction)
    ///
    /// Returns Ok(true) if the claimed time is consistent with pulsar physics,
    /// Ok(false) if the time was spoofed (disagreement exceeds statistical tolerance).
    pub fn verify_astrophysical_timestamp(
        &self,
        pulsar_id: &str,
        observed_pulses: u64,
        claimed_elapsed_seconds: f64,
        observing_frequency_mhz: f64,
    ) -> Result<bool, &'static str> {
        if !observing_frequency_mhz.is_finite()
            || observing_frequency_mhz <= 0.0
            || !claimed_elapsed_seconds.is_finite()
            || claimed_elapsed_seconds < 0.0
        {
            return Err("Invalid radio observing frequency or elapsed time");
        }

        let model = self.catalog.get(pulsar_id).ok_or("Unknown Pulsar ID: not in ATNF catalog")?;

        // Correct claimed elapsed time for dispersion delay
        let disp_delay = model.dispersion_delay_s(observing_frequency_mhz);
        let corrected_elapsed = claimed_elapsed_seconds - disp_delay;

        // Expected pulses based on the timing model (accounts for spin-down)
        let expected_pulses = model.expected_pulses_in_interval(corrected_elapsed);

        // Statistical tolerance: 0.01% (1σ timing residual for MSPs is ~100ns)
        // For claimed times, we allow 0.05% deviation to account for signal processing
        let tolerance = expected_pulses * 0.0005;

        let pulse_residual = (observed_pulses as f64 - expected_pulses).abs();

        if pulse_residual > tolerance {
            Ok(false) // Timestamp is inconsistent with pulsar physics — likely spoofed
        } else {
            Ok(true)  // Timestamp is consistent with cosmic pulsar clock
        }
    }

    /// Perform the full relativistic light-cone verification for a TLS handshake.
    ///
    /// Proves or disproves that a client at the claimed IP location could physically
    /// have produced the observed RTT given the speed of light in optical fiber.
    pub fn verify_light_cone(
        &self,
        client_claimed_lat: f64,
        client_claimed_lon: f64,
        measured_rtt_s: f64,
    ) -> LightConeVerdict {
        let (srv_lat, srv_lon) = self.server_location;

        if !client_claimed_lat.is_finite()
            || !client_claimed_lon.is_finite()
            || !measured_rtt_s.is_finite()
            || measured_rtt_s < 0.0
            || !srv_lat.is_finite()
            || !srv_lon.is_finite()
        {
            return LightConeVerdict {
                claimed_location: (client_claimed_lat, client_claimed_lon),
                server_location: (srv_lat, srv_lon),
                distance_m: 0.0,
                measured_rtt_s,
                min_rtt_fiber_s: 0.0,
                min_rtt_vacuum_s: 0.0,
                is_physically_possible: false,
                spoofing_confidence: 1.0,
                reason: "IMPOSSIBLE: Coordinates or measured RTT are invalid (NaN or negative).".to_string(),
            };
        }

        // Geodesic distance between server and claimed client location
        let distance_m = vincenty_distance(srv_lat, srv_lon, client_claimed_lat, client_claimed_lon);

        // Minimum physically possible RTT through optical fiber (fastest realistic medium)
        let min_rtt_fiber_s = 2.0 * distance_m / C_FIBER;

        // Absolute minimum (speed of light in vacuum — physically impossible to beat)
        let min_rtt_vacuum_s = 2.0 * distance_m / C_LIGHT;

        let is_physically_possible = measured_rtt_s >= min_rtt_vacuum_s;

        // Spoofing confidence: how impossible is this RTT?
        // 0.0 = impossible (measured < vacuum limit), scaling up to 1.0 for massive violations
        let spoofing_confidence = if is_physically_possible {
            // How much faster than fiber is the connection?
            if measured_rtt_s < min_rtt_fiber_s && min_rtt_fiber_s > 1e-12 {
                ((min_rtt_fiber_s - measured_rtt_s) / min_rtt_fiber_s).clamp(0.0, 1.0)
            } else {
                0.0 // Normal connection
            }
        } else {
            1.0 // Physically impossible — definitive spoofing
        };

        let reason = if !is_physically_possible {
            format!(
                "IMPOSSIBLE: RTT {:.3}ms < vacuum speed-of-light limit {:.3}ms for {:.1}km distance. \
                 Client CANNOT be at claimed location ({:.4}°, {:.4}°).",
                measured_rtt_s * 1000.0, min_rtt_vacuum_s * 1000.0, distance_m / 1000.0,
                client_claimed_lat, client_claimed_lon
            )
        } else if spoofing_confidence > 0.1 {
            format!(
                "SUSPICIOUS: RTT {:.3}ms is {:.1}% faster than expected for fiber at {:.1}km. \
                 Possible VPN, CDN proxy, or location spoofing.",
                measured_rtt_s * 1000.0, spoofing_confidence * 100.0, distance_m / 1000.0
            )
        } else {
            format!(
                "VERIFIED: RTT {:.3}ms is physically consistent with {:.1}km distance.",
                measured_rtt_s * 1000.0, distance_m / 1000.0
            )
        };

        LightConeVerdict {
            claimed_location: (client_claimed_lat, client_claimed_lon),
            server_location: (srv_lat, srv_lon),
            distance_m,
            measured_rtt_s,
            min_rtt_fiber_s,
            min_rtt_vacuum_s,
            is_physically_possible,
            spoofing_confidence,
            reason,
        }
    }
}
