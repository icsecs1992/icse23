## Automatic Static Detection of Software Security Vulnerabilities in ML Libraries: Are We There Yet?

Automatic detection of software vulnerabilities is a critical task in software security. Many static tools that can help detect security vulnerabilities have been proposed. While these static vulnerability detectors are mainly evaluated on general software projects call into question their practical effectiveness and usefulness for machine learning libraries. In this paper, we address this question by analyzing four popular and widely used static vulnerability detectors, i.e., Flawfinder, RATS, Cppcheck, and Facebook Infer on a curated dataset of software security vulnerabilities gathered from six popular ML libraries including Mlpack, Numpy, Pandas, Scipy, Pytorch, and Tensorflow with a total of 688 known security vulnerabilities. We use two novel methodologies that combine an automatic analysis of vulnerabilities with a manual validation process to determine which of these vulnerabilities each examined tool can detect. Our research provides a categorization of these tools’ capabilities to better understand the strengths and weaknesses of the tools for detecting software vulnerabilities. Overall, our study shows that static vulnerability detectors find a negligible amount of all vulnerabilities accounting for 3/590 vulnerabilities (0.5%), Cppcheck is the most effective static checker for finding software security vulnerabilities in ML libraries. Based on our observations, we further identify and discuss opportunities to make the tools more effective and practical.

## Steps to reproduce the results

In order to run the scripts in the repository and replicate the results, you need to have the following packages installed:

```
panads 1.3.5
numpy 1.22.3
pydriller 1.15.5
requests 2.26.0
git 3.1.18
```
The vulnerability fixing commits for the studied ML libraries can be found under the ```data/vic_vfs``` directory. But, in order to reproduce the commits, please run the following script:

```
python fetch_commits.py
```

Once you downloaded all vulnerability fixing commits, manual inspection is required to label them based on [CWE](https://cwe.mitre.org/) vulnerability categories.

### 1. Running static checkers

In this paper, we use four widely-used and popular static vulnerability detectors including [Flawfinder](https://dwheeler.com/flawfinder/), [RATS](https://github.com/andrew-d/rough-auditing-tool-for-security), [Cppcheck](https://cppcheck.sourceforge.io/), and [Facebook Infer](https://fbinfer.com/). We apply these detectors on commit files (written in C/C++) and use two well-known mapping techniques to find potential vulnerability candidates. First three detectors are in the same script and Infer is implemented in separate script. To run Flawfinder, RATS, and Cppcheck, please use the following steps:

Change directory to the location where the script exists:

```
cd ICSE23/detectors/script1/ 
```
And run:

```
python run_vfc.py
```
Once you executed the command, the results will be generated under ```ICSE23/detection_results``` folder. 

Infer is isolated because it needs compilation commands to run commit files. The compilation commands are available at ```compilation_database/compile_commands_pytorch.json```. 





