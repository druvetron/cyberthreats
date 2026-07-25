"""
streaming_simulator.py — replays data/raw/access_logs.csv in timestamp
order at a configurable speed multiplier, to demonstrate/benchmark the
near-real-time scoring path (evaluation criterion: "system design &
scalability — real-time streaming feasibility") without needing an actual
Kafka/Kinesis deployment for the hackathon submission.

Planned flow:
    - read CSV sorted by timestamp
    - for each row, sleep for (next_ts - cur_ts) / speed_multiplier
    - push the row to infer.py's scoring function (or a queue.Queue that a
      separate consumer thread drains) and record end-to-end latency
    - report p50/p95/p99 scoring latency and rows/sec throughput at the end
      -> goes straight into reports/report.md's scalability section

TODO — implement:
    def replay(path, speed_multiplier=60, on_row=callback) 
    def benchmark(path, scoring_fn) -> latency percentiles + throughput
"""
