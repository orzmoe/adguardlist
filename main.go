package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	rulesFile         = "setting/rules.txt"
	outputDir         = "rules"
	publishDir        = "publish"
	outputFile        = "output.txt"
	tempMergedFile    = "merged_rules.txt"
	tempCompiledFile  = "compiled_rules.txt"
	maxConcurrentJobs = 8
	downloadTimeout   = 45 * time.Second
)

// downloadResult 保存了下载任务的内容和可能发生的错误。
type downloadResult struct {
	url     string
	content []byte
	err     error
}

// readLines 将整个文件读入内存，并返回一个字符串切片。
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// downloadWorker 是一个工作协程，它从 jobs 通道接收 URL，
// 下载后将结果发送到 results 通道。
func downloadWorker(id int, jobs <-chan string, results chan<- downloadResult, wg *sync.WaitGroup) {
	defer wg.Done()
	client := &http.Client{
		Timeout: downloadTimeout,
	}
	for url := range jobs {
		log.Printf("[Worker %d] Downloading %s\n", id, url)
		var result downloadResult
		result.url = url

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			result.err = fmt.Errorf("failed to create request: %w", err)
			results <- result
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AdRulesBot-Go/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			result.err = fmt.Errorf("http request failed: %w", err)
			results <- result
			continue
		}

		if resp.StatusCode != http.StatusOK {
			result.err = fmt.Errorf("bad status: %s", resp.Status)
			results <- result
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			result.err = fmt.Errorf("failed to read body: %w", err)
			results <- result
			continue
		}

		if len(body) == 0 {
			result.err = fmt.Errorf("downloaded file is empty")
			results <- result
			continue
		}

		result.content = body
		results <- result
	}
}

// countRules 计算文件中的有效规则数量，跳过注释和空行。
func countRules(content []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "!") && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

func main() {
	log.Println("🚀 Starting AdGuard rules processing with Go...")

	// 1. 从规则文件中读取 URL
	urls, err := readLines(rulesFile)
	if err != nil {
		log.Fatalf("❌ Failed to read rules file '%s': %v", rulesFile, err)
	}
	totalSources := len(urls)
	log.Printf("ℹ️ Found %d rule sources in '%s'.", totalSources, rulesFile)

	// 2. 并发下载所有规则
	jobs := make(chan string, totalSources)
	results := make(chan downloadResult, totalSources)
	var wg sync.WaitGroup

	for i := 1; i <= maxConcurrentJobs; i++ {
		wg.Add(1)
		go downloadWorker(i, jobs, results, &wg)
	}

	for _, url := range urls {
		jobs <- url
	}
	close(jobs)

	var successfulDownloads [][]byte
	var failedDownloads []string
	for i := 0; i < totalSources; i++ {
		res := <-results
		if res.err != nil {
			log.Printf("❌ Download failed for %s: %v", res.url, res.err)
			failedDownloads = append(failedDownloads, res.url)
		} else {
			log.Printf("✅ Downloaded %s (%d bytes)", res.url, len(res.content))
			successfulDownloads = append(successfulDownloads, res.content)
		}
	}
	wg.Wait() // 等待所有 worker 完成

	successCount := len(successfulDownloads)
	failedCount := len(failedDownloads)
	log.Printf("📊 Download summary: %d successful, %d failed.", successCount, failedCount)

	if successCount == 0 {
		log.Fatal("❌ No rules were downloaded successfully. Aborting.")
	}

	// 3. 合并已下载的规则
	log.Println("🔄 Merging downloaded rules...")
	mergedContent := bytes.Join(successfulDownloads, []byte("\n"))
	if err := os.WriteFile(tempMergedFile, mergedContent, 0644); err != nil {
		log.Fatalf("❌ Failed to write merged rules to '%s': %v", tempMergedFile, err)
	}
	defer os.Remove(tempMergedFile)

	// 4. 运行 hostlist-compiler
	log.Println("⚙️ Compiling rules with hostlist-compiler...")
	cmd := exec.Command("hostlist-compiler", "-i", tempMergedFile, "-o", tempCompiledFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ hostlist-compiler failed: %v", err)
	}
	defer os.Remove(tempCompiledFile)

	compiledContent, err := os.ReadFile(tempCompiledFile)
	if err != nil {
		log.Fatalf("❌ Failed to read compiled file '%s': %v", tempCompiledFile, err)
	}

	// 5. 生成最终的输出文件
	log.Println("📝 Generating final output file...")
	ruleCount := countRules(compiledContent)
	buildTime := time.Now().Format(time.RFC3339)

	var header bytes.Buffer
	header.WriteString("# Title: 5whys Adguard Home Rules List (Use with a lot of false rejects)\n")
	header.WriteString(fmt.Sprintf("# Version: %s\n", time.Now().Format("200601021504")))
	header.WriteString(fmt.Sprintf("# Generated: %s\n", buildTime))
	header.WriteString("# Expires: 12 hours\n")
	header.WriteString(fmt.Sprintf("# Total sources: %d (Success: %d, Failed: %d)\n", totalSources, successCount, failedCount))
	header.WriteString(fmt.Sprintf("# Total rules: %d\n", ruleCount))
	header.WriteString(fmt.Sprintf("# Homepage: https://github.com/%s\n", os.Getenv("GITHUB_REPOSITORY")))
	header.WriteString("#\n")
	header.WriteString("# Source URLs:\n")
	for _, url := range urls {
		header.WriteString(fmt.Sprintf("# - %s\n", url))
	}
	header.WriteString("#\n")
	header.WriteString("####################################################################################\n\n")

	finalContent := append(header.Bytes(), compiledContent...)

	// 6. 创建目录并写入文件
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("❌ Failed to create output directory '%s': %v", outputDir, err)
	}
	if err := os.MkdirAll(publishDir, 0755); err != nil {
		log.Fatalf("❌ Failed to create publish directory '%s': %v", publishDir, err)
	}

	outputFilePath := filepath.Join(outputDir, outputFile)
	publishFilePath := filepath.Join(publishDir, outputFile)

	if err := os.WriteFile(outputFilePath, finalContent, 0644); err != nil {
		log.Fatalf("❌ Failed to write final output to '%s': %v", outputFilePath, err)
	}
	log.Printf("✅ Wrote output to %s", outputFilePath)

	// 拷贝到 publish 目录
	if err := os.WriteFile(publishFilePath, finalContent, 0644); err != nil {
		log.Fatalf("❌ Failed to copy output to '%s': %v", publishFilePath, err)
	}
	log.Printf("✅ Copied output to %s", publishFilePath)

	// 为后续步骤设置 GITHUB_ENV
	githubEnvFile := os.Getenv("GITHUB_ENV")
	if githubEnvFile != "" {
		f, err := os.OpenFile(githubEnvFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("⚠️ Could not open GITHUB_ENV file: %v", err)
		} else {
			defer f.Close()
			envVars := map[string]int{
				"RULES_COUNT":   ruleCount,
				"SUCCESS_COUNT": successCount,
				"FAILED_COUNT":  failedCount,
				"TOTAL_COUNT":   totalSources,
			}
			for key, val := range envVars {
				if _, err := f.WriteString(fmt.Sprintf("%s=%d\n", key, val)); err != nil {
					log.Printf("⚠️ Failed to write %s to GITHUB_ENV: %v", key, err)
				}
			}
		}
	}

	log.Println("✅ All tasks completed successfully.")
}
