"""CLI entry point for SQL Injection Protector."""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    import click

console = Console() if HAS_RICH else None


def print_output(message: str, style: str = None):
    """Print output with optional rich formatting."""
    if console:
        console.print(message, style=style)
    else:
        print(message)


def print_error(message: str):
    """Print error message."""
    if console:
        console.print(f"[red]Error:[/red] {message}")
    else:
        print(f"Error: {message}", file=sys.stderr)


def print_success(message: str):
    """Print success message."""
    if console:
        console.print(f"[green]✓[/green] {message}")
    else:
        print(f"✓ {message}")


@click.group()
@click.version_option(version="1.0.0", prog_name="sqli-protector")
def cli():
    """SQL Injection Protector AI Agent - CLI Tool.

    Provides command-line interface for:
    - Analyzing text for SQL injection
    - Running the protection server
    - Managing configuration
    - Training and evaluating models
    - Running benchmarks
    """
    pass


@cli.command()
@click.argument("text")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def analyze(text: str, config: Optional[str], output_json: bool, verbose: bool):
    """Analyze text for SQL injection patterns.

    Example:
        sqli-protector analyze "SELECT * FROM users WHERE id=1 OR 1=1"
    """
    async def run_analysis():
        from sql_injection_protector.core.agent import SQLInjectionAgent
        from sql_injection_protector.core.config import load_config

        settings = load_config(config) if config else None
        agent = SQLInjectionAgent(settings=settings)

        if not output_json:
            print_output("Initializing agent...", style="dim")

        await agent.initialize()

        if not output_json:
            print_output("Analyzing input...", style="dim")

        result = await agent.analyze_text(text)

        if output_json:
            output = {
                "is_injection": result.is_injection,
                "confidence": result.confidence,
                "threat_level": result.threat_level.value if result.threat_level else "none",
                "matched_patterns": result.matched_patterns or [],
            }
            click.echo(json.dumps(output, indent=2))
        else:
            # Rich output
            if result.is_injection:
                print_output(f"\n[red bold]⚠ SQL INJECTION DETECTED[/red bold]")
                print_output(f"Confidence: [yellow]{result.confidence:.1%}[/yellow]")
                print_output(f"Threat Level: [red]{result.threat_level.value}[/red]")

                if result.matched_patterns:
                    print_output("\nMatched Patterns:")
                    for pattern in result.matched_patterns:
                        print_output(f"  • {pattern}")
            else:
                print_success("No SQL injection detected")
                print_output(f"Confidence: {result.confidence:.1%}")

        await agent.shutdown()

    asyncio.run(run_analysis())


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", default=8080, type=int, help="Port to bind to")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def serve(host: str, port: int, config: Optional[str], reload: bool):
    """Start the protection server.

    Example:
        sqli-protector serve --host 0.0.0.0 --port 8080 --config config.yaml
    """
    try:
        import uvicorn
    except ImportError:
        print_error("uvicorn is required. Install with: pip install uvicorn")
        sys.exit(1)

    print_output(f"Starting SQL Injection Protector server on {host}:{port}")

    # Set config path in environment
    if config:
        import os
        os.environ["SQLI_PROTECTOR_CONFIG"] = config

    uvicorn.run(
        "sql_injection_protector.app:app",
        host=host,
        port=port,
        reload=reload,
    )


@cli.command()
@click.option("--requests", "-n", default=1000, type=int, help="Number of requests")
@click.option("--payloads", "-p", type=click.Path(exists=True), help="Payloads file (one per line)")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
def benchmark(requests: int, payloads: Optional[str], config: Optional[str], output: Optional[str]):
    """Run performance benchmark.

    Example:
        sqli-protector benchmark --requests 1000 --payloads test_payloads.txt
    """
    async def run_benchmark():
        from sql_injection_protector.core.agent import SQLInjectionAgent
        from sql_injection_protector.core.config import load_config

        settings = load_config(config) if config else None
        agent = SQLInjectionAgent(settings=settings)

        print_output("Initializing agent...")
        await agent.initialize()

        # Load payloads
        test_payloads = []
        if payloads:
            with open(payloads) as f:
                test_payloads = [line.strip() for line in f if line.strip()]
        else:
            # Default test payloads
            test_payloads = [
                "normal search query",
                "SELECT * FROM users",
                "1 OR 1=1",
                "'; DROP TABLE users; --",
                "admin'--",
                "UNION SELECT username, password FROM users",
                "1; WAITFOR DELAY '0:0:5'--",
                "normal text with some numbers 12345",
            ]

        print_output(f"Running benchmark with {requests} requests...")
        print_output(f"Using {len(test_payloads)} unique payloads")

        latencies = []
        detections = 0

        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Benchmarking...", total=requests)

                for i in range(requests):
                    payload = test_payloads[i % len(test_payloads)]

                    start = time.perf_counter()
                    result = await agent.analyze_text(payload)
                    elapsed = time.perf_counter() - start

                    latencies.append(elapsed * 1000)  # Convert to ms
                    if result.is_injection:
                        detections += 1

                    progress.update(task, advance=1)
        else:
            for i in range(requests):
                payload = test_payloads[i % len(test_payloads)]

                start = time.perf_counter()
                result = await agent.analyze_text(payload)
                elapsed = time.perf_counter() - start

                latencies.append(elapsed * 1000)
                if result.is_injection:
                    detections += 1

                if (i + 1) % 100 == 0:
                    print(f"Progress: {i + 1}/{requests}")

        # Calculate statistics
        latencies.sort()
        avg_latency = sum(latencies) / len(latencies)
        p50 = latencies[int(len(latencies) * 0.5)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        min_latency = min(latencies)
        max_latency = max(latencies)

        results = {
            "requests": requests,
            "detections": detections,
            "detection_rate": detections / requests,
            "latency_ms": {
                "avg": round(avg_latency, 2),
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "min": round(min_latency, 2),
                "max": round(max_latency, 2),
            },
            "throughput_rps": round(requests / (sum(latencies) / 1000), 2),
        }

        # Output results
        if HAS_RICH:
            table = Table(title="Benchmark Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Requests", str(results["requests"]))
            table.add_row("Detections", str(results["detections"]))
            table.add_row("Detection Rate", f"{results['detection_rate']:.1%}")
            table.add_row("Throughput", f"{results['throughput_rps']} req/s")
            table.add_row("Avg Latency", f"{results['latency_ms']['avg']:.2f} ms")
            table.add_row("P50 Latency", f"{results['latency_ms']['p50']:.2f} ms")
            table.add_row("P95 Latency", f"{results['latency_ms']['p95']:.2f} ms")
            table.add_row("P99 Latency", f"{results['latency_ms']['p99']:.2f} ms")
            table.add_row("Min Latency", f"{results['latency_ms']['min']:.2f} ms")
            table.add_row("Max Latency", f"{results['latency_ms']['max']:.2f} ms")

            console.print(table)
        else:
            print("\n=== Benchmark Results ===")
            print(f"Total Requests: {results['requests']}")
            print(f"Detections: {results['detections']}")
            print(f"Detection Rate: {results['detection_rate']:.1%}")
            print(f"Throughput: {results['throughput_rps']} req/s")
            print(f"Avg Latency: {results['latency_ms']['avg']:.2f} ms")
            print(f"P50 Latency: {results['latency_ms']['p50']:.2f} ms")
            print(f"P95 Latency: {results['latency_ms']['p95']:.2f} ms")
            print(f"P99 Latency: {results['latency_ms']['p99']:.2f} ms")

        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            print_output(f"Results saved to {output}")

        await agent.shutdown()

    asyncio.run(run_benchmark())


@cli.command()
@click.option("--output", "-o", default="config.yaml", help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["yaml", "json"]), default="yaml")
def init(output: str, fmt: str):
    """Generate default configuration file.

    Example:
        sqli-protector init --output my-config.yaml
    """
    from sql_injection_protector.core.config import Settings

    settings = Settings()

    if fmt == "yaml":
        try:
            import yaml
            config_dict = settings.model_dump()
            with open(output, "w") as f:
                yaml.dump({"sql_injection_protector": config_dict}, f, default_flow_style=False)
        except ImportError:
            print_error("PyYAML required for YAML output. Install with: pip install pyyaml")
            sys.exit(1)
    else:
        config_dict = settings.model_dump()
        with open(output, "w") as f:
            json.dump({"sql_injection_protector": config_dict}, f, indent=2)

    print_success(f"Configuration file created: {output}")


@cli.command()
@click.argument("config_file", type=click.Path(exists=True))
def validate(config_file: str):
    """Validate a configuration file.

    Example:
        sqli-protector validate config.yaml
    """
    from sql_injection_protector.core.config import load_config
    from sql_injection_protector.core.exceptions import ConfigurationError

    try:
        settings = load_config(config_file)
        print_success(f"Configuration file is valid: {config_file}")

        if HAS_RICH:
            # Show summary
            print_output("\nConfiguration Summary:")
            print_output(f"  Detection Model: {settings.detection.model_type}")
            print_output(f"  Block Threshold: {settings.decision.block_threshold}")
            print_output(f"  Rate Limiting: {'Enabled' if settings.rate_limiting.enabled else 'Disabled'}")
            print_output(f"  Honeypot: {'Enabled' if settings.honeypot.enabled else 'Disabled'}")
            print_output(f"  Learning Mode: {'Enabled' if settings.decision.learning_mode else 'Disabled'}")

    except ConfigurationError as e:
        print_error(f"Invalid configuration: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error loading configuration: {e}")
        sys.exit(1)


@cli.command()
@click.argument("dataset", type=click.Path(exists=True))
@click.option("--model-type", type=click.Choice(["tfidf", "transformer"]), default="tfidf")
@click.option("--output", "-o", required=True, help="Output model path")
@click.option("--epochs", "-e", default=10, type=int, help="Training epochs (transformer only)")
@click.option("--batch-size", "-b", default=32, type=int, help="Batch size")
def train(dataset: str, model_type: str, output: str, epochs: int, batch_size: int):
    """Train a new detection model.

    Dataset should be a CSV or JSONL file with 'text' and 'label' columns.

    Example:
        sqli-protector train data/training.csv --model-type tfidf --output models/v2/
    """
    async def run_training():
        print_output(f"Training {model_type} model...")
        print_output(f"Dataset: {dataset}")
        print_output(f"Output: {output}")

        # Load dataset
        import csv
        texts = []
        labels = []

        with open(dataset) as f:
            if dataset.endswith(".csv"):
                reader = csv.DictReader(f)
                for row in reader:
                    texts.append(row["text"])
                    labels.append(int(row["label"]))
            else:  # JSONL
                for line in f:
                    row = json.loads(line)
                    texts.append(row["text"])
                    labels.append(int(row["label"]))

        print_output(f"Loaded {len(texts)} samples")
        print_output(f"Positive: {sum(labels)}, Negative: {len(labels) - sum(labels)}")

        if model_type == "tfidf":
            from sql_injection_protector.layers.detection.ml.tfidf import TFIDFDetector

            detector = TFIDFDetector()
            await detector.train(texts, labels)
            await detector.save(output)

        else:  # transformer
            try:
                from sql_injection_protector.layers.detection.ml.transformer import TransformerDetector

                detector = TransformerDetector()
                await detector.train(
                    texts,
                    labels,
                    epochs=epochs,
                    batch_size=batch_size,
                    output_path=output,
                )
            except ImportError:
                print_error("Transformer training requires: pip install transformers torch")
                sys.exit(1)

        print_success(f"Model saved to {output}")

    asyncio.run(run_training())


@cli.command()
@click.argument("model_path", type=click.Path(exists=True))
@click.argument("test_data", type=click.Path(exists=True))
@click.option("--model-type", type=click.Choice(["tfidf", "transformer"]), default="tfidf")
def evaluate(model_path: str, test_data: str, model_type: str):
    """Evaluate a trained model.

    Example:
        sqli-protector evaluate models/v1/ test_data.csv --model-type tfidf
    """
    async def run_evaluation():
        print_output(f"Evaluating {model_type} model...")

        # Load test data
        import csv
        texts = []
        labels = []

        with open(test_data) as f:
            if test_data.endswith(".csv"):
                reader = csv.DictReader(f)
                for row in reader:
                    texts.append(row["text"])
                    labels.append(int(row["label"]))
            else:
                for line in f:
                    row = json.loads(line)
                    texts.append(row["text"])
                    labels.append(int(row["label"]))

        print_output(f"Loaded {len(texts)} test samples")

        # Load model
        if model_type == "tfidf":
            from sql_injection_protector.layers.detection.ml.tfidf import TFIDFDetector
            detector = TFIDFDetector(model_path=model_path)
        else:
            from sql_injection_protector.layers.detection.ml.transformer import TransformerDetector
            detector = TransformerDetector(model_path=model_path)

        await detector.load()

        # Evaluate
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0

        for text, label in zip(texts, labels):
            is_sqli, confidence = await detector.predict(text)
            predicted = 1 if is_sqli else 0

            if predicted == 1 and label == 1:
                true_positives += 1
            elif predicted == 0 and label == 0:
                true_negatives += 1
            elif predicted == 1 and label == 0:
                false_positives += 1
            else:
                false_negatives += 1

        # Calculate metrics
        total = len(labels)
        accuracy = (true_positives + true_negatives) / total
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        if HAS_RICH:
            table = Table(title="Evaluation Results")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Accuracy", f"{accuracy:.2%}")
            table.add_row("Precision", f"{precision:.2%}")
            table.add_row("Recall", f"{recall:.2%}")
            table.add_row("F1 Score", f"{f1:.2%}")
            table.add_row("True Positives", str(true_positives))
            table.add_row("True Negatives", str(true_negatives))
            table.add_row("False Positives", str(false_positives))
            table.add_row("False Negatives", str(false_negatives))

            console.print(table)
        else:
            print("\n=== Evaluation Results ===")
            print(f"Accuracy: {accuracy:.2%}")
            print(f"Precision: {precision:.2%}")
            print(f"Recall: {recall:.2%}")
            print(f"F1 Score: {f1:.2%}")
            print(f"TP: {true_positives}, TN: {true_negatives}")
            print(f"FP: {false_positives}, FN: {false_negatives}")

    asyncio.run(run_evaluation())


@cli.command(name="interactive")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
def interactive_mode(config: Optional[str]):
    """Start interactive analysis mode.

    Type SQL queries or text to analyze. Type 'exit' to quit.

    Example:
        sqli-protector interactive
    """
    async def run_interactive():
        from sql_injection_protector.core.agent import SQLInjectionAgent
        from sql_injection_protector.core.config import load_config

        settings = load_config(config) if config else None
        agent = SQLInjectionAgent(settings=settings)

        print_output("Initializing SQL Injection Protector...")
        await agent.initialize()

        if HAS_RICH:
            console.print(Panel.fit(
                "[bold]SQL Injection Protector - Interactive Mode[/bold]\n\n"
                "Enter text to analyze for SQL injection patterns.\n"
                "Type 'exit' or 'quit' to exit.",
                border_style="blue"
            ))
        else:
            print("\n=== SQL Injection Protector - Interactive Mode ===")
            print("Enter text to analyze. Type 'exit' to quit.\n")

        while True:
            try:
                if HAS_RICH:
                    text = console.input("[bold blue]>[/bold blue] ")
                else:
                    text = input("> ")

                if text.lower() in ("exit", "quit", "q"):
                    break

                if not text.strip():
                    continue

                result = await agent.analyze_text(text)

                if result.is_injection:
                    print_output(
                        f"[red]⚠ INJECTION DETECTED[/red] | "
                        f"Confidence: [yellow]{result.confidence:.1%}[/yellow] | "
                        f"Level: [red]{result.threat_level.value}[/red]"
                    )
                    if result.matched_patterns:
                        print_output(f"  Patterns: {', '.join(result.matched_patterns[:3])}")
                else:
                    print_output(f"[green]✓ Clean[/green] | Confidence: {result.confidence:.1%}")

            except (KeyboardInterrupt, EOFError):
                break

        print_output("\nShutting down...")
        await agent.shutdown()

    asyncio.run(run_interactive())


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
