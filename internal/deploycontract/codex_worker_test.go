package deploycontract

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCodexImplementationWorkerUsesNonInteractiveAuthorityContract(t *testing.T) {
	t.Parallel()

	worker, err := os.ReadFile("../../workers/codex-implementation/worker.sh")
	if err != nil {
		t.Fatalf("read Codex implementation worker: %v", err)
	}

	violations := codexExecContractViolations(string(worker))
	if len(violations) > 0 {
		t.Errorf("Codex implementation worker authority contract violations:\n%s", strings.Join(violations, "\n"))
	}
}

func TestCodexExecContractRejectsForbiddenTerminalSandbox(t *testing.T) {
	t.Parallel()

	worker := "codex exec \\\n" +
		"  --ephemeral \\\n" +
		"  --dangerously-bypass-approvals-and-sandbox \\\n" +
		"  --sandbox workspace-write\n"
	violations := codexExecContractViolations(worker)

	if !contains(violations, `must not use weaker or undocumented authority option "--sandbox"`) {
		t.Fatalf("terminal --sandbox argument was not rejected; violations: %q", violations)
	}
}

func TestCodexExecContractRejectsDuplicateOneLineInvocationWithAlternateWhitespace(t *testing.T) {
	t.Parallel()

	worker := "codex\texec --ephemeral --dangerously-bypass-approvals-and-sandbox; codex    exec --ephemeral --dangerously-bypass-approvals-and-sandbox\n"
	violations := codexExecContractViolations(worker)

	if !contains(violations, "must have exactly one codex exec invocation; found 2") {
		t.Fatalf("duplicate one-line invocation was not rejected; violations: %q", violations)
	}
}

func codexExecContractViolations(worker string) []string {
	invocations, err := parseCodexExecInvocations(worker)
	if err != nil {
		return []string{fmt.Sprintf("could not parse Codex implementation worker: %v", err)}
	}
	if len(invocations) != 1 {
		return []string{fmt.Sprintf("must have exactly one codex exec invocation; found %d", len(invocations))}
	}

	args := invocations[0]
	violations := make([]string, 0)
	for _, flag := range []string{
		"--ephemeral",
		"--dangerously-bypass-approvals-and-sandbox",
	} {
		if count(args, flag) != 1 {
			violations = append(violations, fmt.Sprintf("must invoke codex exec with exactly one %s; args: %q", flag, args))
		}
	}

	for _, arg := range args {
		if arg == "--full-auto" || arg == "--yolo" || strings.HasPrefix(arg, "--ask-for-approval") || strings.HasPrefix(arg, "--sandbox") {
			violations = append(violations, fmt.Sprintf("must not use weaker or undocumented authority option %q; args: %q", arg, args))
		}
	}
	return violations
}

type shellToken struct {
	text     string
	operator bool
	newline  bool
}

func parseCodexExecInvocations(worker string) ([][]string, error) {
	tokens, err := tokenizeShell(worker)
	if err != nil {
		return nil, err
	}

	var invocations [][]string
	commandStart := true
	for index := 0; index < len(tokens); {
		token := tokens[index]
		if token.newline || isCommandSeparator(token) {
			commandStart = true
			index++
			continue
		}
		if token.operator {
			index++
			continue
		}
		if !commandStart {
			index++
			continue
		}

		commandStart = false
		if token.text != "codex" || index+1 >= len(tokens) || tokens[index+1].operator || tokens[index+1].newline || tokens[index+1].text != "exec" {
			index++
			continue
		}

		args := []string{"codex", "exec"}
		index += 2
		for index < len(tokens) && !tokens[index].newline && !isCommandSeparator(tokens[index]) {
			if tokens[index].operator {
				if isRedirection(tokens[index]) && index+1 < len(tokens) {
					index += 2
					continue
				}
				return nil, fmt.Errorf("unsupported shell operator %q in codex exec command", tokens[index].text)
			}
			args = append(args, tokens[index].text)
			index++
		}
		invocations = append(invocations, args)
	}
	return invocations, nil
}

func tokenizeShell(input string) ([]shellToken, error) {
	tokens := make([]shellToken, 0)
	for index := 0; index < len(input); {
		switch input[index] {
		case ' ', '\t', '\r':
			index++
		case '\n':
			tokens = append(tokens, shellToken{newline: true})
			index++
		case '#':
			for index < len(input) && input[index] != '\n' {
				index++
			}
		case ';', '|', '&', '>', '<', '(', ')':
			start := index
			index++
			if index < len(input) && (input[index] == input[start] || (input[start] == '&' && input[index] == '>')) {
				index++
			}
			tokens = append(tokens, shellToken{text: input[start:index], operator: true})
		default:
			word, next, err := shellWord(input, index)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, shellToken{text: word})
			index = next
		}
	}
	return tokens, nil
}

func shellWord(input string, start int) (string, int, error) {
	var word strings.Builder
	for index := start; index < len(input); {
		switch input[index] {
		case ' ', '\t', '\r', '\n', ';', '|', '&', '>', '<', '(', ')':
			return word.String(), index, nil
		case '\\':
			if index+1 == len(input) {
				return "", 0, fmt.Errorf("unterminated escape")
			}
			if input[index+1] != '\n' {
				word.WriteByte(input[index+1])
			}
			index += 2
		case '\'', '"':
			quote := input[index]
			index++
			for index < len(input) && input[index] != quote {
				if quote == '"' && input[index] == '\\' && index+1 < len(input) {
					if input[index+1] != '\n' {
						word.WriteByte(input[index+1])
					}
					index += 2
					continue
				}
				word.WriteByte(input[index])
				index++
			}
			if index == len(input) {
				return "", 0, fmt.Errorf("unterminated %q quote", quote)
			}
			index++
		default:
			word.WriteByte(input[index])
			index++
		}
	}
	return word.String(), len(input), nil
}

func isCommandSeparator(token shellToken) bool {
	return token.operator && (token.text == ";" || token.text == "&&" || token.text == "||" || token.text == "|" || token.text == "&")
}

func isRedirection(token shellToken) bool {
	return token.text == ">" || token.text == ">>" || token.text == "<" || token.text == "<<" || token.text == "&>"
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func count(args []string, want string) int {
	count := 0
	for _, arg := range args {
		if arg == want {
			count++
		}
	}
	return count
}
