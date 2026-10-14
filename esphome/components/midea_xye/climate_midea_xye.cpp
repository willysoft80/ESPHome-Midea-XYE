#ifdef USE_ARDUINO

#include "climate_midea_xye.h"

#include "esphome/core/log.h"

#include <cstring>

namespace esphome {
namespace midea {
namespace xye {

const char *const Constants::TAG = "midea_xye";
const char *const Constants::FREEZE_PROTECTION = "Freeze Protection";
const char *const Constants::SILENT = "Silent";
const char *const Constants::TURBO = "Turbo";

std::vector<std::pair<uart::UARTComponent *, ClimateMideaXYE *>> ClimateMideaXYE::bus_claims_{};

bool ClimateMideaXYE::try_claim_bus_() {
  for (auto &claim : bus_claims_) {
    if (claim.first == this->uart_) {
      if (claim.second != nullptr && claim.second != this)
        return false;  // another instance is mid-transaction on this bus
      claim.second = this;
      return true;
    }
  }
  bus_claims_.emplace_back(this->uart_, this);
  return true;
}

void ClimateMideaXYE::release_bus_() {
  for (auto &claim : bus_claims_) {
    if (claim.first == this->uart_ && claim.second == this)
      claim.second = nullptr;
  }
}

bool ClimateMideaXYE::reply_head_ok_(const uint8_t *p, uint8_t cmd_sent) const {
  // A reply echoes the command, marks itself as unit -> master, is addressed to
  // the master on both destination bytes and carries the polled unit's ID.
  return p[0] == static_cast<uint8_t>(ProtocolMarker::PREAMBLE) &&
         p[RX_OFFSET_COMMAND] == cmd_sent &&  // responses echo the command byte
         (p[RX_OFFSET_DIRECTION] & RX_DIRECTION_REPLY_MASK) == static_cast<uint8_t>(TO_CLIENT) &&
         // replies are addressed to the master (ID 0x00)
         p[RX_OFFSET_DESTINATION1] == CLIENT_ID && p[RX_OFFSET_DESTINATION2] == CLIENT_ID &&
         p[RX_OFFSET_SOURCE] == this->address_;
}

bool ClimateMideaXYE::extract_frame_(const uint8_t *buf, size_t n, uint8_t cmd_sent) {
  if (n < RX_MESSAGE_LENGTH)
    return false;
  // The reply starts at the first head that passes the structural check. Later
  // heads in the same window - the start of a second frame sent back-to-back
  // (observed: Clivet IB3-XY 53M), or noise - are never considered: a chance
  // checksum match on them would publish garbage as a reading.
  size_t off = 0;
  while (off + RX_HEADONLY_TRUSTED_LENGTH <= n) {
    // A transceiver that echoes the master's own frame puts it first in the
    // window, and at address 0x00 its head reads like a reply: skip it.
    if (off + TX_MESSAGE_LENGTH <= n && memcmp(&buf[off], this->last_tx_, TX_MESSAGE_LENGTH) == 0) {
      off += TX_MESSAGE_LENGTH;
      continue;
    }
    if (this->reply_head_ok_(&buf[off], cmd_sent))
      break;
    off++;
  }
  if (off + RX_HEADONLY_TRUSTED_LENGTH > n)
    return false;
  // Pass 1: CRC-verified frames only.
  // Standard fixed-length frame at this offset?
  if (off + RX_MESSAGE_LENGTH <= n) {
    memcpy(rx_data.raw, &buf[off], RX_MESSAGE_LENGTH);
    if (rx_data.is_valid()) {
      this->rx_trusted_len_ = RX_MESSAGE_LENGTH;
      // More bytes after a checksum-valid frame mean a burst (observed: Clivet
      // IB3-XY 53M), where the one-byte checksum can match garbled bytes by
      // chance: trust only the head then, so a fluke never latches a value.
      if (off + RX_MESSAGE_LENGTH != n) {
        memset(rx_data.raw + RX_HEADONLY_TRUSTED_LENGTH, 0, RX_MESSAGE_LENGTH - RX_HEADONLY_TRUSTED_LENGTH);
        rx_data.message.frame_end.prologue = ProtocolMarker::PROLOGUE;
        rx_data.message.frame_end.crc = compute_protocol_crc(rx_data.raw, RX_MESSAGE_LENGTH);
        this->rx_trusted_len_ = RX_HEADONLY_TRUSTED_LENGTH;
      }
      return true;
    }
  }
  // Extended variable-length frame: same head layout, dialect-specific extra
  // payload, CRC and prologue only at the very end. Accept when the whole
  // span checksums, then synthesize a standard frame from the trusted head so
  // ParseResponse can treat it like any other response.
  for (size_t end = off + RX_MESSAGE_LENGTH + 1; end <= n; end++) {
    if (buf[end - 1] != static_cast<uint8_t>(ProtocolMarker::PROLOGUE))
      continue;
    const uint8_t span = static_cast<uint8_t>(end - off);
    if (buf[end - 2] != compute_protocol_crc(&buf[off], span))
      continue;
    // The checksum is one byte and is tried at every terminator in the
    // window, so a garbled tail matches by chance about once per 256
    // candidates: only the head is trusted.
    memcpy(rx_data.raw, &buf[off], RX_HEADONLY_TRUSTED_LENGTH);
    memset(rx_data.raw + RX_HEADONLY_TRUSTED_LENGTH, 0, RX_MESSAGE_LENGTH - RX_HEADONLY_TRUSTED_LENGTH);
    rx_data.message.frame_end.prologue = ProtocolMarker::PROLOGUE;
    rx_data.message.frame_end.crc = compute_protocol_crc(rx_data.raw, RX_MESSAGE_LENGTH);
    this->rx_trusted_len_ = RX_HEADONLY_TRUSTED_LENGTH;
    ESP_LOGD(Constants::TAG, "Accepted extended %u-byte response from unit 0x%02X", span, this->address_);
    return true;
  }
  // Pass 2 (fallback): head-only acceptance. Some units (observed: Clivet
  // IB3-XY 53M) transmit a second frame back-to-back after the response with no
  // inter-frame gap; the UART loses bit sync at the junction and everything
  // past the head - including the real CRC - is garbled beyond recovery. The
  // head itself arrives intact on every poll, so accept it when it passes a
  // strict structural check AND the burst still ends with the protocol
  // terminator, then zero the unverifiable remainder.
  // A lone frame whose checksum failed is not such a burst: its corruption
  // can be anywhere, head included.
  if (n <= off + RX_MESSAGE_LENGTH)
    return false;
  if (buf[n - 1] != static_cast<uint8_t>(ProtocolMarker::PROLOGUE))
    return false;  // burst must still end with the protocol terminator
  memcpy(rx_data.raw, &buf[off], RX_HEADONLY_TRUSTED_LENGTH);
  memset(rx_data.raw + RX_HEADONLY_TRUSTED_LENGTH, 0, RX_MESSAGE_LENGTH - RX_HEADONLY_TRUSTED_LENGTH);
  rx_data.message.frame_end.prologue = ProtocolMarker::PROLOGUE;
  rx_data.message.frame_end.crc = compute_protocol_crc(rx_data.raw, RX_MESSAGE_LENGTH);
  this->rx_trusted_len_ = RX_HEADONLY_TRUSTED_LENGTH;
  ESP_LOGD(Constants::TAG, "Accepted head-only response (%u of %u bytes) from unit 0x%02X",
           static_cast<unsigned>(RX_HEADONLY_TRUSTED_LENGTH), static_cast<unsigned>(n), this->address_);
  return true;
}

static void set_sensor(Sensor *sensor, float value) {
  if (sensor != nullptr && (!sensor->has_state() || sensor->get_raw_state() != value))
    sensor->publish_state(value);
}

static void set_number(number::Number *number, float value) {
  if (number != nullptr && (!number->has_state() || number->state != value))
    number->publish_state(value);
}

#ifdef USE_BINARY_SENSOR
static void set_binary_sensor(binary_sensor::BinarySensor *sens, bool value) {
  if (sens != nullptr && (!sens->has_state() || sens->state != value))
    sens->publish_state(value);
}
#endif

template<typename T> void update_property(T &property, const T &value, bool &flag) {
  if (property != value) {
    property = value;
    flag = true;
  }
}

void ClimateMideaXYE::control(const ClimateCall &call) {
  if (call.get_mode().has_value()) {
    this->mode = call.get_mode().value();
    // Reset Follow-Me initialization flag when mode changes to ensure
    // proper initialization sequence is sent on next Follow-Me update
    followMeInit = false;
  }
  if (call.get_target_temperature().has_value())
    this->target_temperature = call.get_target_temperature().value();
  if (call.get_fan_mode().has_value())
    this->fan_mode = call.get_fan_mode().value();
  if (call.get_swing_mode().has_value())
    this->swing_mode = call.get_swing_mode().value();
  if (call.get_preset().has_value())
    this->preset = call.get_preset().value();
  this->publish_state();

  if (controlState != ControlState::WAIT_DATA) {
    controlState = ControlState::SEND_SET;
  } else {
    queuedCommand = ControlState::SEND_SET;
  }
}

void ClimateMideaXYE::setup() {
  // this->uart_->check_uart_settings(4800, 1, UART_CONFIG_PARITY_NONE, 8);
  this->last_on_mode_ = *this->supported_modes_.begin();
  controlState = ControlState::SEND_QUERY;
  queuedCommand = ControlState::WAIT_DATA;
  ForceReadNextCycle = 1;
  followMeInit = false;

  // Register custom modes on the Climate base class. ESPHome 2026.4.0
  // deprecated the equivalent ClimateTraits setters in favor of these.
  this->set_supported_custom_presets(this->supported_custom_presets_);
  this->set_supported_custom_fan_modes(this->supported_custom_fan_modes_);

  // Start up in Auto fan mode (since unit doesn't report it correctly)
  this->fan_mode = ClimateFanMode::CLIMATE_FAN_AUTO;
}

void ClimateMideaXYE::set_follow_me_sensor(Sensor *sensor) {
  this->follow_me_sensor_ = sensor;
  if (sensor != nullptr) {
    sensor->add_on_state_callback([this](float state) { this->on_follow_me_sensor_update_(state); });
  }
}

// TODO: Not sure if we really need this.
void ClimateMideaXYE::setPowerState(bool state) {
  if (state)
    this->mode = this->last_on_mode_;
  else
    this->mode = ClimateMode::CLIMATE_MODE_OFF;

  if (controlState != ControlState::WAIT_DATA) {
    controlState = ControlState::SEND_SET;
  } else {
    queuedCommand = ControlState::SEND_SET;
  }
}

void ClimateMideaXYE::setTransmitParams() {
  tx_data = TransmitData(Command::SET, this->address_);
  auto &d = tx_data.message.data.standard;

  d.operation_mode = XYEAdapter::get_operation_mode(this->mode);

  if (this->mode != ClimateMode::CLIMATE_MODE_HEAT_COOL) {
    d.fan_mode = XYEAdapter::get_fan_mode(this->fan_mode.value());
  } else {
    // Auto is full-auto - can't set fan mode either.
    this->fan_mode = ClimateFanMode::CLIMATE_FAN_AUTO;
    d.fan_mode = FanMode::FAN_AUTO;
  }

  // Data always comes in as C, but user may want it set in F.
  d.target_temperature.value = XYEAdapter::get_raw_target_temperature(this->target_temperature, this->use_fahrenheit_);

  d.mode_flags = XYEAdapter::get_mode_flags(
      this->preset.value_or(ClimatePreset::CLIMATE_PRESET_NONE), this->swing_mode);

  tx_data.update_crc();
}

void ClimateMideaXYE::sendRecv(uint8_t cmdSent) {
  // TODO: Reimplement flow control for manual RS485 flow control chips
  // digitalWrite(ComControlPin, RS485_TX_PIN_VALUE);
  // Drop any stale bytes (a late reply to a previous poll, or another unit's
  // traffic) so the read window below only ever sees this frame's response.
  uint8_t stale;
  while (this->uart_->available())
    this->uart_->read_byte(&stale);
  // Log outgoing message at debug level
  tx_data.print_debug(Constants::TAG, TX_MESSAGE_LENGTH, ESPHOME_LOG_LEVEL_DEBUG);
  // The reply echoes the command byte of the frame actually on the wire, which
  // is not always cmdSent (on the SEND_FOLLOWME step tx_data can still hold
  // the SET frame). Captured now: tx_data can be rebuilt during WAIT_DATA.
  const uint8_t wire_cmd = static_cast<uint8_t>(tx_data.message.frame.header.command);
  memcpy(this->last_tx_, tx_data.raw, TX_MESSAGE_LENGTH);
  this->uart_->write_array(tx_data.raw, TX_MESSAGE_LENGTH);
  this->uart_->flush();
  controlState = ControlState::WAIT_DATA;
  // Delay for response_timeout ms to allow response from the AC unit.
  this->set_timeout("read-result", this->response_timeout, [this, cmdSent, wire_cmd]() {
    // digitalWrite(ComControlPin, RS485_RX_PIN_VALUE);

    // Read the whole window into a scratch buffer, then SCAN it for a response
    // frame instead of assuming the buffer holds exactly one fixed-length frame:
    // some units answer with extra bytes around/after the standard response.
    uint8_t buf[BUS_RX_SCAN_BUFFER_SIZE];
    size_t n = 0;
    uint8_t discard;
    while (this->uart_->available()) {
      if (n < sizeof(buf)) {
        this->uart_->read_byte(&buf[n]);
        n++;
      } else {
        this->uart_->read_byte(&discard);
      }
    }
    // Transaction over either way: free the bus for any other instance.
    this->release_bus_();
    // extract_frame_ also enforces the Source ID (response byte 4), so on a
    // shared bus a frame from any other unit is never accepted.
    if (this->extract_frame_(buf, n, wire_cmd)) {
      // The configured address answered: the bus is responsive, clear the miss
      // counter so a transient gap never accumulates toward a needless sweep.
      this->miss_count_ = 0;
      this->comm_misses_ = 0;
#ifdef USE_BINARY_SENSOR
      set_binary_sensor(this->communication_sensor_, true);
#endif
      // A unit answered at the active address; surface it so the sensor never
      // sits at "Unknown" for a unit that responds at its configured address
      // (i.e. one that never triggered an auto-discovery sweep).
      this->publish_discovered_address_();
      // Log incoming message at debug level
      rx_data.print_debug(RX_MESSAGE_LENGTH, Constants::TAG, ESPHOME_LOG_LEVEL_DEBUG, this->use_fahrenheit_);
      // Don't parse responses to SET or FOLLOW_ME commands to avoid
      // overwriting the mode we just set. The AC state will be updated
      // on subsequent QUERY cycles.
      // Likewise skip a poll response that was already in flight when
      // control() queued a SET: it carries the unit's state from before the
      // command, and parsing it would overwrite the requested mode/setpoint/fan
      // that setTransmitParams() is about to send - the SET would then carry
      // the old state and the command would be silently lost.
      if (cmdSent != CLIENT_COMMAND_SET && cmdSent != CLIENT_COMMAND_FOLLOWME &&
          queuedCommand != ControlState::SEND_SET) {
        ParseResponse();
      }
      if (queuedCommand != ControlState::WAIT_DATA) {
        controlState = queuedCommand;
        queuedCommand = ControlState::WAIT_DATA;
      } else {
        switch (cmdSent) {
          case CLIENT_COMMAND_QUERY:
            controlState = ControlState::SEND_QUERY_EXTENDED;
            break;
          case CLIENT_COMMAND_SET:
            controlState = ControlState::SEND_FOLLOWME;
            break;
          case CLIENT_COMMAND_QUERY_EXTENDED:
            controlState = ControlState::SEND_QUERY;
            break;
          case CLIENT_COMMAND_FOLLOWME:
            controlState = ControlState::SEND_QUERY;
            break;
        }
      }
    } else {
      // Distinguish a true no-reply from a window with bytes but no usable
      // frame. On a silent bus (wrong unit address, miswired/unterminated bus,
      // or no unit present) this branch fires every poll cycle, so logging the
      // expected 0-byte case at WARN would spam a warning every ~second. Log
      // no-reply at DEBUG and reserve WARN for a window that carried bytes in
      // which no valid frame from the polled unit could be found (noise, a
      // frame from another unit, or an unknown dialect), which is genuinely
      // suspicious and worth surfacing.
      if (n == 0) {
        ESP_LOGD(Constants::TAG, "No response for command %02X", cmdSent);
      } else {
        ESP_LOGW(Constants::TAG, "No valid frame from unit 0x%02X in %u byte(s) for Command %02X; resyncing",
                 this->address_, static_cast<unsigned>(n), cmdSent);
      }
      // Recover instead of deadlocking in WAIT_DATA: a missed, short, or
      // over-long reply must not strand the state machine. Honor any queued
      // command, otherwise restart the poll cycle on the next update().
      if (queuedCommand != ControlState::WAIT_DATA) {
        controlState = queuedCommand;
        queuedCommand = ControlState::WAIT_DATA;
      } else {
        controlState = ControlState::SEND_QUERY;
      }
      if (this->comm_misses_ < COMMUNICATION_LOST_AFTER_MISSES)
        this->comm_misses_++;
#ifdef USE_BINARY_SENSOR
      if (this->comm_misses_ >= COMMUNICATION_LOST_AFTER_MISSES)
        set_binary_sensor(this->communication_sensor_, false);
#endif
      // After recovering, count this miss and (if enabled) start an address
      // sweep once the bus has been unresponsive for discovery_after_ cycles.
      this->maybe_start_discovery_();
    }
    // The SET has gone out: send what was deferred while it was pending.
    // If its miss started an address sweep, the SET is not retried, so drop
    // the deferred requests too instead of replaying them after a later SET.
    if (cmdSent == CLIENT_COMMAND_SET && !this->set_pending_()) {
      if (this->discovering_) {
        if (this->follow_me_deferred_ || this->static_pressure_deferred_) {
          ESP_LOGD(Constants::TAG, "Unit unresponsive; deferred request dropped");
        }
        this->follow_me_deferred_ = false;
        this->static_pressure_deferred_ = false;
      } else {
        this->send_deferred_();
      }
    }
  });
}

void ClimateMideaXYE::maybe_start_discovery_() {
  // Called from the no-response path. Count consecutive unanswered polls and,
  // when auto-discovery is enabled and the bus has stayed silent long enough,
  // kick off an address sweep. Only runs while the configured address is dead.
  if (!this->auto_discover_ || this->discovering_)
    return;
  if (++this->miss_count_ < this->discovery_after_)
    return;
  this->discovering_ = true;
  this->scan_addr_ = this->scan_min_;
#ifdef USE_BINARY_SENSOR
  // Polling pauses during the sweep, so report the lost unit now rather than
  // leaving the sensor on until a sweep with a low discovery_after ends.
  set_binary_sensor(this->communication_sensor_, false);
#endif
  ESP_LOGW(Constants::TAG, "Address 0x%02X unresponsive for %u cycles; scanning 0x%02X-0x%02X for a unit",
           this->address_, this->miss_count_, this->scan_min_, this->scan_max_);
  this->send_probe_();
}

void ClimateMideaXYE::send_probe_() {
  // Send one C0 (QUERY) to the current scan address and wait response_timeout.
  // A CRC-valid reply whose source ID matches the probed address means a unit
  // lives there. The sweep chains via set_timeout, so it runs at ~response_timeout
  // per address independent of the (slower) poll period; normal polling stays
  // suspended (see update()) so only one frame is ever in flight.
  //
  // Probes respect shared-bus arbitration too: on a bus with several instances,
  // never transmit a probe over another instance's pending reply.
  if (!this->try_claim_bus_()) {
    this->set_timeout("discover-gap", BUS_BUSY_RETRY_DELAY_MS, [this]() { this->send_probe_(); });
    return;
  }
  // Drop any stale bytes first (e.g. a late reply to the previous probe) so this
  // probe's read window only sees a response to this address.
  uint8_t stale;
  while (this->uart_->available())
    this->uart_->read_byte(&stale);
  this->tx_data = TransmitData(Command::QUERY, this->scan_addr_);
  this->tx_data.update_crc();
  this->tx_data.print_debug(Constants::TAG, TX_MESSAGE_LENGTH, ESPHOME_LOG_LEVEL_DEBUG);
  this->uart_->write_array(this->tx_data.raw, TX_MESSAGE_LENGTH);
  this->uart_->flush();
  this->set_timeout("discover-read", this->response_timeout, [this]() {
    uint8_t i = 0;
    while (this->uart_->available()) {
      if (i < RX_MESSAGE_LENGTH)
        this->uart_->read_byte(&this->rx_data.raw[i]);
      i++;
    }
    // Probe transaction over: free the bus between probes so other instances
    // can interleave their polls with a (possibly long) address sweep.
    this->release_bus_();
    const bool found = (i == RX_MESSAGE_LENGTH) && this->rx_data.is_valid() &&
                       (this->rx_data.message.frame.header.source == this->scan_addr_);
    if (found) {
      this->finish_discovery_(true, this->scan_addr_);
    } else if (this->scan_addr_ >= this->scan_max_) {
      this->finish_discovery_(false, 0x00);
    } else {
      this->scan_addr_++;
      this->set_timeout("discover-gap", 10, [this]() { this->send_probe_(); });
    }
  });
}

void ClimateMideaXYE::finish_discovery_(bool found, uint8_t addr) {
  this->discovering_ = false;
  this->miss_count_ = 0;
  if (found) {
    ESP_LOGI(Constants::TAG, "Discovered unit at address 0x%02X (was polling 0x%02X); adopting it", addr,
             this->address_);
    this->address_ = addr;
    this->publish_discovered_address_();
  } else {
    ESP_LOGW(Constants::TAG, "Address scan found no unit in 0x%02X-0x%02X; resuming polls at 0x%02X",
             this->scan_min_, this->scan_max_, this->address_);
  }
  // A SET requested during the sweep is still pending: send it first.
  if (!this->set_pending_())
    this->controlState = ControlState::SEND_QUERY;
}

void ClimateMideaXYE::publish_discovered_address_() {
  set_sensor(this->discovered_address_sensor_, static_cast<float>(this->address_));
}

void ClimateMideaXYE::update() {
  uint8_t cmdSent = 0x00;
  // While an address sweep is running it drives itself via chained timeouts;
  // suspend the normal poll cycle so there is never more than one frame in flight.
  if (this->discovering_)
    return;
  // Shared-bus arbitration: when several instances poll units on one UART, only
  // one transaction may be in flight — like a real CCM polling one unit at a time.
  // If another instance holds the bus, retry shortly instead of transmitting over
  // its pending reply.
  if (controlState != ControlState::WAIT_DATA && !this->try_claim_bus_()) {
    if (this->bus_retry_count_ < BUS_BUSY_MAX_RETRIES) {
      this->bus_retry_count_++;
      this->set_timeout("bus-retry", BUS_BUSY_RETRY_DELAY_MS, [this]() { this->update(); });
    } else {
      this->bus_retry_count_ = 0;  // give up this cycle; the next poll starts over
    }
    return;
  }
  this->bus_retry_count_ = 0;
  // Possible States:
  // 0: Waiting for Response from Command
  // 1: Sending Set C3 Command
  // 2: Sending Set C6 Command
  // 3: Sending Query C0 Command
  // 4: Sending Query C4 Command
  switch (controlState) {
    case ControlState::SEND_SET: {
      setTransmitParams();
      post_set_grace_ = 2;
      cmdSent = CLIENT_COMMAND_SET;
      sendRecv(cmdSent);
      break;
    }
    case ControlState::SEND_FOLLOWME: {
      // If the AC mode changed, follow-me should be
      // refreshed, if emulating the wired controller's
      // behavior.
      cmdSent = CLIENT_COMMAND_FOLLOWME;
      sendRecv(cmdSent);
      if (this->mode == ClimateMode::CLIMATE_MODE_OFF) {
        ESP_LOGI(Constants::TAG, "Set static pressure.");
      } else {
        ESP_LOGI(Constants::TAG, "Sent Follow-Me data.");
      }
      break;
    }
    case ControlState::SEND_QUERY: {
      tx_data = TransmitData(Command::QUERY, this->address_);
      tx_data.update_crc();
      cmdSent = CLIENT_COMMAND_QUERY;
      sendRecv(cmdSent);
      break;
    }
    case ControlState::SEND_QUERY_EXTENDED: {
      tx_data = TransmitData(Command::QUERY_EXTENDED, this->address_);
      tx_data.update_crc();
      cmdSent = CLIENT_COMMAND_QUERY_EXTENDED;
      sendRecv(cmdSent);
      break;
    }
    case ControlState::WAIT_DATA: {
      // Wait for data to processed. Do nothing during the loop.
      break;
    }
  }
}

void ClimateMideaXYE::ParseResponse() {
  if (!rx_data.is_valid()) {
    ESP_LOGE(Constants::TAG, "Received invalid response from AC");
    rx_data.print_debug(RX_MESSAGE_LENGTH, Constants::TAG, ESPHOME_LOG_LEVEL_ERROR);
    return;
  }

  switch (rx_data.message.frame.header.command) {
    case Command::QUERY: {
      const auto &qr = rx_data.message.data.query_response;
      ClimatePreset preset = ClimatePreset::CLIMATE_PRESET_NONE;

      const ClimateMode mode = XYEAdapter::get_climate_mode(qr.operation_mode);
      const ClimateFanMode fan_mode = XYEAdapter::get_climate_fan_mode(qr.fan_mode);

      if (static_cast<uint8_t>(qr.mode_flags) & MODE_FLAG_AUX_HEAT)
        preset = ClimatePreset::CLIMATE_PRESET_BOOST;
      else if (static_cast<uint8_t>(qr.mode_flags) & MODE_FLAG_ECO)
        preset = ClimatePreset::CLIMATE_PRESET_SLEEP;

      bool need_publish = false;

      if (post_set_grace_ > 0) {
        post_set_grace_--;
        ESP_LOGD(Constants::TAG,
                 "Post-SET grace: ignoring reported mode=%d (%u cycle(s) remaining)",
                 static_cast<int>(mode), post_set_grace_);
      } else {
        update_property(this->mode, mode, need_publish);
        if (mode != ClimateMode::CLIMATE_MODE_OFF) {
          this->last_on_mode_ = mode;
        }
      }

      // The indoor coil/room temperature (t1) is a physical reading that is valid whether
      // or not the unit is actively conditioning, so it must be published on every valid C0
      // response — not gated on mode. Otherwise, with no follow-me sensor supplying
      // current_temperature through a separate path, Home Assistant sees null whenever the
      // unit reads OFF (which, on some VRF indoor units, is what C0 reports even while running).
      this->internal_temperature_ = XYEAdapter::get_temperature(qr.t1_temperature.value);

      // Publish the internal temperature to the sensor if configured
      set_sensor(this->internal_current_temperature_sensor_, this->internal_temperature_);

      // Update current_temperature based on sensor availability
      this->update_current_temperature_from_sensors_(need_publish);

      if (mode != ClimateMode::CLIMATE_MODE_OFF || ForceReadNextCycle == 1) {
        // Target temperature is read from C4 (QUERY_EXTENDED) by default. Opt-in
        // (target_temperature_from_c0): read it from this C0 frame instead, for units
        // that never answer C4 (e.g. some Mini VRF indoor units) and would otherwise leave
        // target_temperature null. C0 carries the setpoint in the same encoding
        // get_target_temperature() decodes for C4 — Celsius raw with the 0x40 status flag,
        // or (°F + FAHRENHEIT_TEMP_OFFSET) in Fahrenheit mode. Respect post_set_grace_ so a
        // freshly-sent SET is not immediately overwritten by stale device state. When enabled,
        // the C4 handler skips its own target read so the two sources never fight.
        if (this->target_temperature_from_c0_ && post_set_grace_ == 0) {
          update_property(this->target_temperature,
                          XYEAdapter::get_target_temperature(qr.target_temperature.value, this->use_fahrenheit_),
                          need_publish);
        }

        // Compressor/defrost-aware action is opt-in (compressor_aware_action) while the
        // C0 byte-19 compressor flag is still provisional. When disabled, compressor_active=true
        // and defrost_active=false reproduce the legacy "fan running implies heating/cooling".
        const bool compressor_active = !this->compressor_aware_action_ ||
                                       qr.compressor_running_flag == CompressorRunningFlag::ACTIVE;
        // Protect flags past the trusted bytes are synthesized zeros: treat defrost
        // as unknown (inactive), exactly as before, rather than as a reading.
        const bool defrost_active = this->compressor_aware_action_ &&
                                    this->rx_trusted_(RX_OFFSET_C0_PROTECT_FLAGS, sizeof(qr.protect_flags)) &&
                                    XYEAdapter::is_defrost_active(qr.protect_flags.value());
        update_property(this->action,
                        XYEAdapter::get_climate_action(mode, qr.fan_mode, qr.operation_mode,
                                                       compressor_active, defrost_active),
                        need_publish);

        if ((this->swing_mode != ClimateSwingMode::CLIMATE_SWING_OFF) !=
            (bool) (static_cast<uint8_t>(qr.mode_flags) & MODE_FLAG_SWING))
          need_publish = true;
        this->swing_mode = (static_cast<uint8_t>(qr.mode_flags) & MODE_FLAG_SWING)
                               ? ClimateSwingMode::CLIMATE_SWING_VERTICAL
                               : ClimateSwingMode::CLIMATE_SWING_OFF;
        if (this->preset != preset)
          need_publish = true;
        this->preset = preset;
      } else if ((this->action != climate::CLIMATE_ACTION_IDLE) &&
                 (static_cast<uint8_t>(qr.fan_mode) & FAN_SPEED_MASK) == 0x00) {
        this->action = climate::CLIMATE_ACTION_IDLE;
        need_publish = true;
      }

      if (need_publish)
        this->publish_state();

      set_sensor(this->temperature_2a_sensor_, XYEAdapter::get_temperature(qr.t2a_temperature.value));
      set_sensor(this->temperature_2b_sensor_, XYEAdapter::get_temperature(qr.t2b_temperature.value));
      set_sensor(this->temperature_3_sensor_, XYEAdapter::get_temperature(qr.t3_temperature.value));
      set_sensor(this->current_sensor_, static_cast<float>(qr.current));
      set_sensor(this->timer_start_sensor_, CalculateGetTime(qr.timer_start));
      set_sensor(this->timer_stop_sensor_, CalculateGetTime(qr.timer_stop));
      // Error/protect flags lie past the head-only trusted length; on a head-only
      // or extended frame they were zero-filled, so keep the last real reading
      // instead of publishing a fake "no error / no protection / no defrost".
      const bool error_trusted = this->rx_trusted_(RX_OFFSET_C0_ERROR_FLAGS, sizeof(qr.error_flags));
      const bool protect_trusted = this->rx_trusted_(RX_OFFSET_C0_PROTECT_FLAGS, sizeof(qr.protect_flags));
      if (error_trusted)
        set_sensor(this->error_flags_sensor_, static_cast<float>(qr.error_flags.value()));
      if (protect_trusted)
        set_sensor(this->protect_flags_sensor_, static_cast<float>(qr.protect_flags.value()));
      set_sensor(this->fan_speed_sensor_, static_cast<float>(XYEAdapter::get_fan_speed_level(qr.fan_mode)));
#ifdef USE_BINARY_SENSOR
      if (protect_trusted)
        set_binary_sensor(this->defrost_sensor_, XYEAdapter::is_defrost_active(qr.protect_flags.value()));
      set_binary_sensor(this->compressor_active_sensor_,
                        qr.compressor_running_flag == CompressorRunningFlag::ACTIVE);
#endif
      break;
    }
    case Command::QUERY_EXTENDED: {
      bool need_publish = false;
      const auto &exr = rx_data.message.data.extended_query_response;
      // Same rule as the C0 flags: on a head-only or extended frame these bytes were
      // zero-filled (a zero outdoor byte decodes to -20 °C), so skip them.
      if (this->rx_trusted_(RX_OFFSET_C4_OUTDOOR_TEMPERATURE, sizeof(exr.outdoor_temperature)))
        set_sensor(this->outdoor_sensor_, XYEAdapter::get_temperature(exr.outdoor_temperature.value));
      if (this->rx_trusted_(RX_OFFSET_C4_STATIC_PRESSURE, sizeof(exr.static_pressure)))
        set_number(this->static_pressure_number_, static_cast<float>(STATIC_PRESSURE_VALUE_MASK & exr.static_pressure));
      // C4 is the default source for target_temperature, covering both unit modes:
      //  - Fahrenheit: encoded as (°F + FAHRENHEIT_TEMP_OFFSET); convert to Celsius for ESPHome.
      //  - Celsius:    raw integer degrees with bit 6 (0x40) status flag; mask before use.
      // Respect post_set_grace_: skip until the C0 grace window has closed so a freshly-sent
      // SET command isn't immediately overwritten by stale device state.
      // When target_temperature_from_c0 is opted into, C0 is authoritative for the setpoint,
      // so skip the C4 read here to avoid the two sources fighting.
      // Fahrenheit C4 decode approach adapted from rmounce/esphome@xye-units-switch.
      if (!this->target_temperature_from_c0_ &&
          (this->mode != ClimateMode::CLIMATE_MODE_OFF || ForceReadNextCycle == 1) &&
          post_set_grace_ == 0) {
        const float incoming_target_temp =
            XYEAdapter::get_target_temperature(exr.target_temperature.value, this->use_fahrenheit_);
        update_property(this->target_temperature, incoming_target_temp, need_publish);
      }
      if (need_publish)
        this->publish_state();
      // Sync fan mode from the C4 target_fan_speed field when enabled. This is the commanded
      // speed as set on the physical thermostat and persists when the fan is idle, unlike
      // C0 fan_mode which reads 0x00 when stopped.
      // Respect post_set_grace_: if a SET was just issued the device may not yet have
      // updated its reported target_fan_speed, so skip until C0 has cleared the grace window.
      if (this->sync_fan_mode_from_device_ && post_set_grace_ == 0) {
        bool fan_need_publish = false;
        const ClimateFanMode new_fan_mode = XYEAdapter::get_climate_fan_mode(exr.target_fan_speed);
        if (!this->fan_mode.has_value() || this->fan_mode.value() != new_fan_mode) {
          this->fan_mode = new_fan_mode;
          fan_need_publish = true;
        }
        if (fan_need_publish)
          this->publish_state();
      }
      // Note: Previous versions validated fixed protocol marker bytes (0xBC, 0xD6, 0x80, 0x80, 0x80, 0x80)
      // but investigation shows these bytes are actually dynamic engineering values:
      // - Bytes 19-20 (0xBCD6): 16-bit compressor frequency or outdoor fan RPM
      // - Bytes 26-29 (0x80): Subsystem OK flags (compressor, outdoor fan, 4-way valve, inverter)
      // The validation has been removed to support all unit models correctly.
      ForceReadNextCycle = 0;
      break;
    }
    default:
      break;
  }
}

uint8_t ClimateMideaXYE::CalculateSetTime(uint32_t time) {
  uint32_t current_time = time;
  uint8_t timeValue = 0;

  if (0 < (current_time / 960)) {
    timeValue |= 0x40;
    current_time = current_time % 960;
  }
  if (0 < (current_time / 480)) {
    timeValue |= 0x20;
    current_time = current_time % 480;
  }
  if (0 < (current_time / 240)) {
    timeValue |= 0x10;
    current_time = current_time % 240;
  }
  if (0 < (current_time / 120)) {
    timeValue |= 0x08;
    current_time = current_time % 120;
  }
  if (0 < (current_time / 60)) {
    timeValue |= 0x04;
    current_time = current_time % 60;
  }
  if (0 < (current_time / 30)) {
    timeValue |= 0x02;
    current_time = current_time % 30;
  }
  if (0 < (current_time / 15)) {
    timeValue |= 0x01;
    current_time = current_time % 15;
  }
  return timeValue;
}

uint32_t ClimateMideaXYE::CalculateGetTime(uint8_t time) {
  uint32_t timeValue = 0;

  if (time & 0x40) {
    timeValue += 960;
  }
  if (time & 0x20) {
    timeValue += 480;
  }
  if (time & 0x10) {
    timeValue += 240;
  }
  if (time & 0x08) {
    timeValue += 120;
  }
  if (time & 0x04) {
    timeValue += 60;
  }
  if (time & 0x02) {
    timeValue += 30;
  }
  if (time & 0x01) {
    timeValue += 15;
  }
  return timeValue;
}

climate::ClimateTraits ClimateMideaXYE::traits() {
  auto traits = climate::ClimateTraits();
  traits.add_feature_flags(climate::CLIMATE_SUPPORTS_CURRENT_TEMPERATURE);
  traits.add_feature_flags(climate::CLIMATE_SUPPORTS_ACTION);
  traits.set_visual_min_temperature(17);
  traits.set_visual_max_temperature(30);
  traits.set_visual_temperature_step(1.0);
  traits.set_visual_current_temperature_step(VISUAL_CURRENT_TEMPERATURE_STEP);
  traits.set_supported_modes(this->supported_modes_);
  traits.set_supported_swing_modes(this->supported_swing_modes_);
  traits.set_supported_presets(this->supported_presets_);
  /* + MINIMAL SET OF CAPABILITIES */
  traits.add_supported_fan_mode(ClimateFanMode::CLIMATE_FAN_AUTO);
  traits.add_supported_fan_mode(ClimateFanMode::CLIMATE_FAN_LOW);
  traits.add_supported_fan_mode(ClimateFanMode::CLIMATE_FAN_MEDIUM);
  traits.add_supported_fan_mode(ClimateFanMode::CLIMATE_FAN_HIGH);
  traits.add_supported_fan_mode(ClimateFanMode::CLIMATE_FAN_OFF);  // Can't set it but will be reported

  if (!traits.get_supported_modes().empty())
    traits.add_supported_mode(ClimateMode::CLIMATE_MODE_OFF);
  if (!traits.get_supported_swing_modes().empty())
    traits.add_supported_swing_mode(ClimateSwingMode::CLIMATE_SWING_OFF);
  if (!traits.get_supported_presets().empty())
    traits.add_supported_preset(ClimatePreset::CLIMATE_PRESET_NONE);

  return traits;
}

void ClimateMideaXYE::dump_config() {
  ESP_LOGCONFIG(Constants::TAG, "MideaXYE:");
  ESP_LOGCONFIG(Constants::TAG, "  [x] Period: %dms", this->get_update_interval());
  ESP_LOGCONFIG(Constants::TAG, "  [x] Response timeout: %dms", this->response_timeout);
  ESP_LOGCONFIG(Constants::TAG, "  [x] Use Fahrenheit: %d", this->use_fahrenheit_);

#ifdef USE_REMOTE_TRANSMITTER
  ESP_LOGCONFIG(Constants::TAG, "  [x] Using RemoteTransmitter");
#endif
  this->dump_traits_(Constants::TAG);
}

/* ACTIONS */

void ClimateMideaXYE::do_follow_me(float temperature, bool beeper) {
#ifdef USE_REMOTE_TRANSMITTER
  IrFollowMeData data(static_cast<uint8_t>(lroundf(temperature)), beeper);
  this->transmitter_.transmit(data);
#else
  // A pending SET carries the user's latest command. Queuing Follow-Me now
  // would replace it (both go through controlState/queuedCommand) and the SET
  // would be lost; the reading is kept and sent right after the SET instead.
  if (this->set_pending_()) {
    lastFollowMeTemperature = static_cast<uint8_t>(lroundf(temperature));
    this->follow_me_deferred_ = true;
    ESP_LOGD(Constants::TAG, "SET pending; Follow-Me update deferred");
    return;
  }
  this->follow_me_deferred_ = false;

  // Prepare Follow-Me command for temperature update
  tx_data = TransmitData(Command::FOLLOW_ME, this->address_);
  auto &d = tx_data.message.data.standard;

  // timer_stop is a subcommand type field for Follow-Me commands.
  // Subcommand values: 0x06=Init, 0x02=Update, 0x04=Static pressure
  // The followMeInit flag tracks whether we've sent the initialization command.
  // It gets reset to false whenever the AC mode changes (see control() function),
  // ensuring a proper initialization sequence after mode changes.
  d.timer_stop = followMeInit ? FOLLOWME_SUBCOMMAND_UPDATE : FOLLOWME_SUBCOMMAND_INIT;
  if (!followMeInit)
    followMeInit = true;
  lastFollowMeTemperature = static_cast<uint8_t>(lroundf(temperature));
  d.mode_flags = static_cast<ModeFlags>(lastFollowMeTemperature);
  tx_data.update_crc();
  // Only send if mode is something other than off.
  // Wired controller does not send Follow-Me command when off.
  if (this->mode != ClimateMode::CLIMATE_MODE_OFF) {
    if (controlState != ControlState::WAIT_DATA) {
      controlState = ControlState::SEND_FOLLOWME;
    } else {
      queuedCommand = ControlState::SEND_FOLLOWME;
    }
    ESP_LOGI(Constants::TAG, "Queued Follow-Me data.");
  }
#endif
}

void ClimateMideaXYE::set_static_pressure(uint8_t static_pressure) {
  if (static_pressure > 15) {
    ESP_LOGW(Constants::TAG, "Cannot set static pressure %d > 15", static_pressure);
    return;
  }
  // Same rule as Follow-Me: never replace a pending SET (e.g. the power-off
  // that must precede a static pressure change); send it right after the SET.
  if (this->set_pending_()) {
    this->deferred_static_pressure_ = static_pressure;
    this->static_pressure_deferred_ = true;
    ESP_LOGD(Constants::TAG, "SET pending; static pressure %u deferred", static_pressure);
    return;
  }
  this->static_pressure_deferred_ = false;

  // Prepare Follow-Me command for static pressure setting
  tx_data = TransmitData(Command::FOLLOW_ME, this->address_);
  auto &d = tx_data.message.data.standard;
  d.target_temperature.value = static_cast<uint8_t>(STATIC_PRESSURE_FLAG | (static_pressure & STATIC_PRESSURE_VALUE_MASK));
  d.timer_stop = FOLLOWME_SUBCOMMAND_STOP;
  d.mode_flags = static_cast<ModeFlags>(lastFollowMeTemperature);
  tx_data.update_crc();

  if (this->mode == ClimateMode::CLIMATE_MODE_OFF) {
    if (controlState != ControlState::WAIT_DATA) {
      controlState = ControlState::SEND_FOLLOWME;
    } else {
      queuedCommand = ControlState::SEND_FOLLOWME;
    }
    ESP_LOGI(Constants::TAG, "Queued setting static pressure to %d", static_pressure);
  } else {
    ESP_LOGW(Constants::TAG, "Cannot set static pressure while unit is running");
  }
}

void ClimateMideaXYE::send_deferred_() {
  // One C6 slot follows the SET: static pressure applies only to a unit that
  // is off, Follow-Me only to one that is on, so the mode the SET left picks.
  const bool follow_me = this->follow_me_deferred_;
  const bool static_pressure = this->static_pressure_deferred_;
  this->follow_me_deferred_ = false;
  this->static_pressure_deferred_ = false;
  if (this->mode == ClimateMode::CLIMATE_MODE_OFF) {
    if (static_pressure)
      this->set_static_pressure(this->deferred_static_pressure_);
  } else if (follow_me) {
    this->do_follow_me(this->lastFollowMeTemperature, false);
  }
}

void ClimateMideaXYE::do_swing_step() {
#ifdef USE_REMOTE_TRANSMITTER
  IrSpecialData data(0x01);
  this->transmitter_.transmit(data);
#else
  ESP_LOGW(Constants::TAG, "Action needs remote_transmitter component");
#endif
}

void ClimateMideaXYE::do_display_toggle() {
#ifdef USE_REMOTE_TRANSMITTER
  IrSpecialData data(0x08);
  this->transmitter_.transmit(data);
#else
  ESP_LOGW(Constants::TAG, "Action needs remote_transmitter component");
#endif
}

void ClimateMideaXYE::on_follow_me_sensor_update_(float state) {
  if (std::isnan(state)) {
    return;
  }
  
  // Update current_temperature with the sensor value
  bool need_publish = false;
  this->update_current_temperature_from_sensors_(need_publish);
  if (need_publish) {
    this->publish_state();
  }

  // Send follow_me command with the sensor temperature
  this->do_follow_me(state, false);
}

void ClimateMideaXYE::update_current_temperature_from_sensors_(bool &need_publish) {
  // Use follow_me_sensor as current_temperature if available, otherwise use internal temperature
  if (this->follow_me_sensor_ != nullptr && this->follow_me_sensor_->has_state() &&
      !std::isnan(this->follow_me_sensor_->state)) {
    update_property(this->current_temperature, this->follow_me_sensor_->state, need_publish);
  } else if (!std::isnan(this->internal_temperature_)) {
    update_property(this->current_temperature, this->internal_temperature_, need_publish);
  }
}

}  // namespace xye
}  // namespace midea
}  // namespace esphome

#endif  // USE_ARDUINO
