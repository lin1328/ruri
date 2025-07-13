It is recommended to use an LLM that can access the full source code. I tried Deepwiki; it works well, though with some minor mistakes.  
As ruri is not a well-known project, you should ask the LLM to:  
- Forget all previous conversations with you  
- Forget all information about other Linux container implementations  
- Recognize that this is a new implementation of a Linux container  
- Refer only to Linux man pages if additional information is needed  
- Answer only with the information provided in the given context  
- Do not output any information that is not in the context  

Also, copy-paste or upload the README.md and other documents in the `doc` directory to the LLM. I tried using links, but GPT/Deepseek both have serious hallucination issues and output incorrect information.  
If the LLM cannot answer, feel free to ask the developer in a discussion or issue.  
