import subprocess

def run_binwalk(path):
    """
    Run binwalk and parse the plain text output into a structured list.
    """
    try:
        result = subprocess.run(
            ["binwalk", path],
            capture_output=True,
            text=True
        )
        if result.returncode not in [0, 1]:  # 1 = warnings
            return {
                "error": f"Binwalk failed with code {result.returncode}: {result.stderr.strip()}"
            }

        lines = result.stdout.splitlines()
        parsed_results = []
        parsing = False

        for line in lines:
            if line.strip() == "":
                continue
            if line.strip().startswith("DECIMAL"):
                parsing = True
                continue
            if parsing and line[0].isdigit():
                parts = line.strip().split(None, 2)
                if len(parts) == 3:
                    offset, _, description = parts
                    parsed_results.append({
                        "offset": offset,
                        "description": description
                    })

        return parsed_results

    except FileNotFoundError:
        return {"error": "binwalk not found. Please install it with 'sudo apt install binwalk'"}
    except Exception as e:
        return {"error": str(e)}
