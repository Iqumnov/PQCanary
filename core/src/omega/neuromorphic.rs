use std::f64::consts::E;

// ============================================================
// Leaky Integrate-and-Fire (LIF) Neuron with RK4 ODE Solver
// ============================================================

/// Leaky Integrate-and-Fire neuron parameters.
#[derive(Clone, Debug)]
pub struct LifNeuron {
    pub v_mem: f64,           // Membrane potential (mV)
    pub v_rest: f64,          // Resting potential (mV)
    pub v_thresh: f64,        // Spike threshold (mV)
    pub v_reset: f64,         // Post-spike reset potential (mV)
    pub r_m: f64,             // Membrane resistance (MΩ)
    pub tau_m: f64,           // Membrane time constant (ms)
    pub refractory: usize,    // Refractory period (simulation ticks)
    pub tau_ref: f64,         // Refractory time constant (ms)
    current_refractory: usize,
    /// Accumulated synaptic current injection this tick (nA)
    pub i_syn: f64,
    /// Total spikes fired (for rate computation)
    pub spike_count: u64,
}

impl Default for LifNeuron {
    fn default() -> Self {
        Self::new()
    }
}

impl LifNeuron {
    pub fn new() -> Self {
        Self {
            v_mem: -70.0,
            v_rest: -70.0,
            v_thresh: -55.0,
            v_reset: -75.0,
            r_m: 10.0,
            tau_m: 20.0,
            refractory: 5,
            tau_ref: 2.0,
            current_refractory: 0,
            i_syn: 0.0,
            spike_count: 0,
        }
    }

    /// LIF ODE right-hand side: dV/dt = [-(V - V_rest) + R_m * I_ext] / tau_m
    fn dv_dt(&self, v: f64, i_ext: f64) -> f64 {
        let tau = if self.tau_m > 1e-12 { self.tau_m } else { 1e-12 };
        (-(v - self.v_rest) + self.r_m * i_ext) / tau
    }

    /// Step using the Euler method (first-order, fast but less accurate)
    pub fn step_euler(&mut self, i_ext: f64, dt: f64) -> bool {
        if self.current_refractory > 0 {
            self.current_refractory -= 1;
            self.v_mem = self.v_reset; // Clamp during refractory
            return false;
        }

        let dv = self.dv_dt(self.v_mem, i_ext);
        self.v_mem += dv * dt;

        if self.v_mem >= self.v_thresh {
            self.v_mem = self.v_reset;
            self.current_refractory = self.refractory;
            self.spike_count += 1;
            return true;
        }
        false
    }

    /// Step using the 4th-order Runge-Kutta method (RK4).
    /// Dramatically more accurate for stiff membrane dynamics.
    /// dV/dt = f(t, V) = [-(V - V_rest) + R_m * I] / τ_m
    pub fn step_rk4(&mut self, i_ext: f64, dt: f64) -> bool {
        if self.current_refractory > 0 {
            self.current_refractory -= 1;
            self.v_mem = self.v_reset;
            return false;
        }

        // RK4 stages
        let k1 = self.dv_dt(self.v_mem, i_ext);
        let k2 = self.dv_dt(self.v_mem + 0.5 * dt * k1, i_ext);
        let k3 = self.dv_dt(self.v_mem + 0.5 * dt * k2, i_ext);
        let k4 = self.dv_dt(self.v_mem + dt * k3, i_ext);

        self.v_mem += (dt / 6.0) * (k1 + 2.0 * k2 + 2.0 * k3 + k4);

        if self.v_mem >= self.v_thresh {
            self.v_mem = self.v_reset;
            self.current_refractory = self.refractory;
            self.spike_count += 1;
            return true;
        }
        false
    }

    /// Inject synaptic current (called by synapse delivery)
    pub fn inject_current(&mut self, amount: f64) {
        self.i_syn += amount;
    }

    /// Consume and reset the accumulated synaptic current
    pub fn consume_synaptic_current(&mut self) -> f64 {
        let i = self.i_syn;
        self.i_syn = 0.0;
        i
    }

    /// Firing rate in Hz given elapsed time (ms)
    pub fn firing_rate_hz(&self, elapsed_ms: f64) -> f64 {
        if elapsed_ms <= 0.0 { return 0.0; }
        (self.spike_count as f64 / elapsed_ms) * 1000.0 // Convert ms⁻¹ to Hz
    }
}

// ============================================================
// Exponential Synapse (Alpha Function) with Axonal Delay
// ============================================================

/// An Alpha-function synapse: current pulse with rise/decay exponential envelope.
/// I_syn(t) = w × (t/τ) × exp(1 - t/τ) — peak at t = τ
#[derive(Clone, Debug)]
pub struct Synapse {
    pub pre_index: usize,
    pub post_index: usize,
    pub weight: f64,          // Synaptic weight (nA peak)
    pub delay: usize,         // Axonal delay (simulation ticks)
    pub tau_syn: f64,         // Synaptic time constant (ms)
    spike_queue: Vec<usize>,  // Spike travel times remaining
    /// Last pre-synaptic spike time for STDP
    pub last_pre_spike: Option<usize>,
    /// Last post-synaptic spike time for STDP
    pub last_post_spike: Option<usize>,
}

impl Synapse {
    pub fn new(pre: usize, post: usize, weight: f64, delay: usize) -> Self {
        Self {
            pre_index: pre,
            post_index: post,
            weight,
            delay,
            tau_syn: 5.0, // 5ms synaptic time constant
            spike_queue: Vec::new(),
            last_pre_spike: None,
            last_post_spike: None,
        }
    }

    /// Compute the alpha function current at time t after synaptic arrival.
    /// I(t) = w × (t / τ) × exp(1 - t/τ) for t ≥ 0
    pub fn alpha_current(&self, t_ms: f64) -> f64 {
        if t_ms < 0.0 || t_ms.is_nan() { return 0.0; }
        let tau = if self.tau_syn > 1e-12 { self.tau_syn } else { 1e-12 };
        let normalized = t_ms / tau;
        self.weight * normalized * E.powf(1.0 - normalized)
    }

    /// Enqueue a new spike arriving from the pre-synaptic neuron.
    pub fn enqueue_spike(&mut self) {
        self.spike_queue.push(self.delay);
    }

    /// Advance the delay queue by one tick and return the peak current if a spike arrives.
    pub fn tick(&mut self) -> f64 {
        let mut delivered_current = 0.0;
        self.spike_queue.retain_mut(|timer| {
            if *timer == 0 {
                // Spike has arrived — inject peak alpha current (t=0 gives I = w*0*e = 0)
                // Use t = tau_syn as the peak (I = w * 1 * e^0 = w)
                delivered_current += self.weight;
                false
            } else {
                *timer -= 1;
                true
            }
        });
        delivered_current
    }
}

// ============================================================
// Spike-Timing Dependent Plasticity (STDP)
// ============================================================

/// STDP learning rule parameters.
/// Implements the classical Bi & Poo (1998) asymmetric STDP window.
#[derive(Debug, Clone)]
pub struct StdpRule {
    /// Amplitude of long-term potentiation (LTP) — weight increase for pre-before-post
    pub a_plus: f64,
    /// Amplitude of long-term depression (LTD) — weight decrease for post-before-pre
    pub a_minus: f64,
    /// Time constant for LTP window (ms)
    pub tau_plus: f64,
    /// Time constant for LTD window (ms)
    pub tau_minus: f64,
    /// Maximum allowed synaptic weight
    pub w_max: f64,
    /// Minimum allowed synaptic weight (can be negative for inhibitory)
    pub w_min: f64,
}

impl StdpRule {
    pub fn canonical_excitatory() -> Self {
        // Bi & Poo (1998) parameters for hippocampal culture
        Self {
            a_plus:    0.01,
            a_minus:   0.012,
            tau_plus:  20.0,
            tau_minus: 20.0,
            w_max:     1.0,
            w_min:     0.0,
        }
    }

    /// Compute the STDP weight update given the time difference Δt = t_pre - t_post (ms).
    /// Δt > 0: pre fires before post → LTP (potentiation)
    /// Δt < 0: post fires before pre → LTD (depression)
    pub fn delta_weight(&self, delta_t_ms: f64) -> f64 {
        if delta_t_ms.is_nan() || self.tau_plus <= 0.0 || self.tau_minus <= 0.0 {
            return 0.0;
        }
        if delta_t_ms > 0.0 {
            // LTP: pre before post
            self.a_plus * (-delta_t_ms / self.tau_plus).exp()
        } else {
            // LTD: post before pre
            -self.a_minus * (delta_t_ms / self.tau_minus).exp()
        }
    }

    /// Apply the STDP update to a synapse weight and clip to [w_min, w_max].
    pub fn update_weight(&self, current_weight: f64, delta_t_ms: f64) -> f64 {
        let dw = self.delta_weight(delta_t_ms);
        (current_weight + dw).max(self.w_min).min(self.w_max)
    }
}

// ============================================================
// Rate Coding: Encode / Decode
// ============================================================

/// Encode a real-valued input (0.0 – 1.0) as a spike rate in Hz using Poisson statistics.
/// Returns a spike train (vec of boolean per tick) at the given time resolution.
pub fn poisson_spike_train(rate_hz: f64, duration_ms: f64, dt_ms: f64) -> Vec<bool> {
    if dt_ms <= 0.0 || duration_ms <= 0.0 || dt_ms.is_nan() || duration_ms.is_nan() || rate_hz.is_nan() {
        return Vec::new();
    }
    let steps_float = (duration_ms / dt_ms).min(100_000.0);
    let n_steps = if steps_float > 0.0 { steps_float as usize } else { 0 };
    let prob_per_step = (rate_hz * dt_ms / 1000.0).clamp(0.0, 1.0);

    // Deterministic pseudo-random generation using a simple LCG for reproducibility
    let mut rng_state: u64 = 12345;
    let mut train = Vec::with_capacity(n_steps);

    for _ in 0..n_steps {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let rand_01 = (rng_state >> 33) as f64 / (u32::MAX as f64);
        train.push(rand_01 < prob_per_step);
    }
    train
}

/// Decode a spike train back to an estimated firing rate (Hz).
pub fn decode_spike_rate(spike_train: &[bool], dt_ms: f64) -> f64 {
    let spike_count = spike_train.iter().filter(|&&s| s).count() as f64;
    let duration_ms = spike_train.len() as f64 * dt_ms;
    if duration_ms <= 0.0 || !duration_ms.is_finite() {
        return 0.0;
    }
    (spike_count / duration_ms) * 1000.0
}

/// Bin spike trains into firing rate estimates using a sliding window (PSTH).
pub fn peri_stimulus_time_histogram(spike_train: &[bool], bin_size_ticks: usize) -> Vec<f64> {
    spike_train.chunks(bin_size_ticks.max(1)).map(|bin| {
        bin.iter().filter(|&&s| s).count() as f64 / bin.len() as f64
    }).collect()
}

// ============================================================
// The Full SNN Compiler and Simulator
// ============================================================

/// Simulation statistics for a completed SNN run.
#[derive(Debug, Clone)]
pub struct SimulationStats {
    pub total_ticks: usize,
    pub total_spikes: u64,
    pub mean_firing_rate_hz: f64,
    pub max_firing_rate_hz: f64,
    pub dt_ms: f64,
    pub duration_ms: f64,
    pub weight_changes: usize,  // Number of STDP weight updates applied
}

/// The full neuromorphic SNN compiler and simulator.
pub struct SnnCompiler {
    neurons: Vec<LifNeuron>,
    synapses: Vec<Synapse>,
    time_step: f64,  // ms
    stdp: Option<StdpRule>,
    tick: usize,
}

impl SnnCompiler {
    pub fn new(time_step: f64) -> Self {
        Self {
            neurons: Vec::new(),
            synapses: Vec::new(),
            time_step,
            stdp: None,
            tick: 0,
        }
    }

    /// Enable STDP learning
    pub fn with_stdp(mut self, rule: StdpRule) -> Self {
        self.stdp = Some(rule);
        self
    }

    /// Add a LIF neuron and return its index.
    pub fn add_neuron(&mut self) -> usize {
        let idx = self.neurons.len();
        self.neurons.push(LifNeuron::new());
        idx
    }

    /// Add a synapse between two neurons.
    pub fn add_synapse(&mut self, pre: usize, post: usize, weight: f64, delay: usize) {
        self.synapses.push(Synapse::new(pre, post, weight, delay));
    }

    /// Simulate the full network for `ticks` steps.
    /// Uses RK4 ODE integration for accuracy.
    ///
    /// `input_currents`: external current per neuron per tick (nA).
    ///   Dimension: [tick][neuron_idx]. If None, zero external input is used.
    #[allow(clippy::needless_range_loop)]
    pub fn simulate(
        &mut self,
        ticks: usize,
        input_currents: &[f64],
    ) -> (Vec<Vec<bool>>, SimulationStats) {
        let num_neurons = self.neurons.len();
        let mut spike_raster = vec![vec![false; ticks]; num_neurons];
        let mut total_spikes = 0u64;
        let mut weight_changes = 0usize;

        for t in 0..ticks {
            self.tick = t;

            // Phase 1: deliver all queued synaptic currents via synapse tick()
            let mut incoming_current = vec![0.0f64; num_neurons];
            for syn in self.synapses.iter_mut() {
                let delivered = syn.tick();
                if delivered > 0.0 {
                    incoming_current[syn.post_index] += delivered;
                }
            }

            // Phase 2: add external stimulation currents
            for (i, neuron) in self.neurons.iter_mut().enumerate() {
                let ext = input_currents.get(i).copied().unwrap_or(0.0);
                incoming_current[i] += ext + neuron.consume_synaptic_current();
            }

            // Phase 3: integrate neuron ODEs (RK4)
            let mut current_spikes = vec![false; num_neurons];
            for (i, neuron) in self.neurons.iter_mut().enumerate() {
                let spiked = neuron.step_rk4(incoming_current[i], self.time_step);
                current_spikes[i] = spiked;
                spike_raster[i][t] = spiked;
                if spiked { total_spikes += 1; }
            }

            // Phase 4: enqueue new spikes into downstream synapses
            for syn in self.synapses.iter_mut() {
                if current_spikes[syn.pre_index] {
                    syn.enqueue_spike();
                    syn.last_pre_spike = Some(t);
                }
                if current_spikes[syn.post_index] {
                    syn.last_post_spike = Some(t);
                }
            }

            // Phase 5: STDP weight update if enabled (only when a spike occurred this tick)
            if let Some(ref stdp_rule) = self.stdp {
                for syn in self.synapses.iter_mut() {
                    let pre_spiked_now = current_spikes[syn.pre_index];
                    let post_spiked_now = current_spikes[syn.post_index];
                    if pre_spiked_now || post_spiked_now {
                        if let (Some(t_pre), Some(t_post)) = (syn.last_pre_spike, syn.last_post_spike) {
                            // t_post >= t_pre means pre fired before or at post (causal -> LTP)
                            // t_post < t_pre means post fired before pre (anti-causal -> LTD)
                            let delta_t = (t_post as f64 - t_pre as f64) * self.time_step;
                            let new_weight = stdp_rule.update_weight(syn.weight, delta_t);
                            if (new_weight - syn.weight).abs() > 1e-9 {
                                syn.weight = new_weight;
                                weight_changes += 1;
                            }
                        }
                    }
                }
            }
        }

        let duration_ms = ticks as f64 * self.time_step;
        let mean_rate = if num_neurons > 0 && duration_ms > 0.0 {
            (total_spikes as f64 / num_neurons as f64 / duration_ms) * 1000.0
        } else { 0.0 };

        let max_rate = self.neurons.iter()
            .map(|n| n.firing_rate_hz(duration_ms))
            .fold(0.0f64, f64::max);

        let stats = SimulationStats {
            total_ticks: ticks,
            total_spikes,
            mean_firing_rate_hz: mean_rate,
            max_firing_rate_hz: max_rate,
            dt_ms: self.time_step,
            duration_ms,
            weight_changes,
        };

        (spike_raster, stats)
    }

    /// Build a standard feedforward triage network for cryptographic signal classification.
    ///
    /// Architecture:
    ///   - `input_size` input neurons (rate-coded vulnerability features)
    ///   - 1 hidden layer of `hidden_size` neurons (feature integration)
    ///   - `output_size` output neurons (vulnerability class votes)
    ///
    /// Weights are initialized with Xavier initialization: w ~ N(0, sqrt(2/(fan_in + fan_out)))
    pub fn build_triage_network(&mut self, input_size: usize, hidden_size: usize, output_size: usize) {
        self.neurons.clear();
        self.synapses.clear();

        // Add input neurons
        for _ in 0..input_size { self.add_neuron(); }

        // Add hidden neurons
        for _ in 0..hidden_size { self.add_neuron(); }

        // Add output neurons
        for _ in 0..output_size { self.add_neuron(); }

        let fan_in_hidden = input_size;
        let fan_in_output = hidden_size;

        // Xavier weight standard deviation
        let xavier_hidden = (2.0 / ((fan_in_hidden + hidden_size).max(1)) as f64).sqrt();
        let xavier_output = (2.0 / ((fan_in_output + output_size).max(1)) as f64).sqrt();

        // Connect input → hidden (fully connected)
        let mut rng: u64 = 0xDEADBEEF_CAFEBABE;
        for i in 0..input_size {
            for h in 0..hidden_size {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let u = (((rng >> 11) as f64) / ((1u64 << 53) as f64)).max(1e-15);
                // Box-Muller transform for Gaussian weight
                let w = xavier_hidden * ((-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * u).cos());
                self.add_synapse(i, input_size + h, w.max(0.0), 1);
            }
        }

        // Connect hidden → output (fully connected)
        for h in 0..hidden_size {
            for o in 0..output_size {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let u = (((rng >> 11) as f64) / ((1u64 << 53) as f64)).max(1e-15);
                let w = xavier_output * ((-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * u).cos());
                self.add_synapse(input_size + h, input_size + hidden_size + o, w.max(0.0), 1);
            }
        }
    }

    /// Classify vulnerability features using rate coding.
    ///
    /// Input features are real values in [0.0, 1.0] mapped to spike rates.
    /// Output class is the index of the output neuron with the highest firing rate.
    pub fn classify(&mut self, features: &[f64], duration_ms: f64) -> usize {
        let dt = if self.time_step > 0.0 && self.time_step.is_finite() { self.time_step } else { 1.0 };
        let ticks = if duration_ms > 0.0 && duration_ms.is_finite() { (duration_ms / dt) as usize } else { 0 };
        let input_size = features.len();
        let total_neurons = self.neurons.len();
        if total_neurons == 0 || ticks == 0 {
            return 0;
        }
        let output_size = total_neurons.saturating_sub(input_size).saturating_sub(
            // Infer hidden size from synapse structure — simplified: use half of total minus input
            input_size
        );

        // Generate Poisson spike trains for each input feature
        let mut input_currents = vec![0.0f64; total_neurons];
        for (i, &feature) in features.iter().enumerate() {
            if i >= total_neurons { break; }
            // Rate coding: feature → current proportional to desired rate
            // Max rate = 100Hz → at dt=0.1ms, rate threshold = 10nA driving 100Hz output
            input_currents[i] = feature * 5.0; // Scale to nA
        }

        // Reset spike counts
        for neuron in self.neurons.iter_mut() {
            neuron.spike_count = 0;
        }

        let (_, _stats) = self.simulate(ticks, &input_currents);

        // Find the output neuron (last output_size neurons) with highest firing rate
        let output_start = total_neurons.saturating_sub(output_size.max(1));
        let rates: Vec<f64> = self.neurons[output_start..]
            .iter()
            .map(|n| n.firing_rate_hz(duration_ms))
            .collect();

        rates.iter().enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
}
