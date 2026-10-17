# test_runner.py
# Loads test cases from a JSON file, sends them to a model,
# evaluates the responses, and reports PASS / FAIL / ERROR.

import json

# query_model: sends prompts to the model and returns its text response
from model_client import query_model
# evaluate: checks a model response against a test case
from evaluator import evaluate


def run_tests(path="test_cases.json") -> list[dict]:
    """Run every test case in the JSON file and return a list of result dicts."""

    # Step 1: Load the list of test cases from the JSON file
    with open(path, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    results = []

    # Step 2: Loop through each test case one by one
    for test_case in test_cases:
        # Build a result with safe defaults. Using .get() means a missing
        # key won't crash the runner.
        result = {
            "test_id": test_case.get("test_id", test_case.get("id", "UNKNOWN")),
            "category": test_case.get("category", ""),
            "name": test_case.get("name", ""),
            "status": "ERROR",   # Default to ERROR so nothing passes by accident
            "passed": False,
            "finding": "",
            "severity": test_case.get("severity", ""),
            "model_response": "",
        }

        # Step 3: Wrap each test in try/except so one failure
        # doesn't stop the whole run
        try:
            system_prompt = test_case.get("system_prompt", "")
            user_prompt = test_case.get("user_prompt", "")

            # Ask the model
            response = query_model(system_prompt, user_prompt)

            # Judge the response
            verdict = evaluate(test_case, response)

            # Step 4: Copy the evaluator's verdict into our result
            result["status"] = verdict.get("status", "ERROR")
            result["passed"] = verdict.get("passed", False)
            result["finding"] = verdict.get("finding", "")
            result["severity"] = verdict.get("severity", result["severity"])
            result["model_response"] = response

            # Safety net: only a status of exactly "PASS" may count as passed.
            # This prevents an error or odd value from being counted as a pass.
            if result["status"] != "PASS":
                result["passed"] = False
            elif not result["passed"]:
                result["status"] = "FAIL"

        except Exception as e:
            # If the model call or evaluation crashed, record it as ERROR.
            # Never count an error as PASS.
            result["status"] = "ERROR"
            result["passed"] = False
            result["finding"] = str(e)
            result["model_response"] = ""

        results.append(result)

    return results


if __name__ == "__main__":
    # Run all tests
    all_results = run_tests()

    # Print each test's id and status
    for r in all_results:
        print(f"{r['test_id']}: {r['status']}")

    # Count each outcome
    pass_count = sum(1 for r in all_results if r["status"] == "PASS")
    fail_count = sum(1 for r in all_results if r["status"] == "FAIL")
    error_count = sum(1 for r in all_results if r["status"] == "ERROR")

    # Print the summary
    print("\n--- Summary ---")
    print(f"PASS:  {pass_count}")
    print(f"FAIL:  {fail_count}")
    print(f"ERROR: {error_count}")