from pathlib import Path
import json
from datetime import datetime
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
import httpx
import yaml
from base_manager import BaseManager
from typing import Optional, Union
import fitz  # PyMuPDF for PDF handling
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tiktoken
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
from langchain.document_loaders import (
    PyPDFLoader,
    TextLoader,
    UnstructuredMarkdownLoader,
    CSVLoader,
    UnstructuredHTMLLoader,
    UnstructuredWordDocumentLoader,
    UnstructuredPowerPointLoader,
    UnstructuredEPubLoader
)
import shutil
from langchain.chat_models import ChatOpenAI
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from langchain.schema import HumanMessage, SystemMessage

class AgentManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.console = Console()
        self.config_dir = Path("config")
        self.data_dir = Path("data/agent")
        self.templates_dir = self.data_dir / "templates"
        self.knowledge_dir = self.data_dir / "knowledge"
        self.reports_dir = self.data_dir / "reports"
        
        # 创建必要的目录
        for dir_path in [self.data_dir, self.templates_dir, 
                        self.knowledge_dir, self.reports_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # 添加新的目录
        self.raw_data_dir = self.data_dir / "raw_data"
        self.vector_db_dir = self.data_dir / "vector_db"
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.vector_db_dir.mkdir(parents=True, exist_ok=True)
        
        self.load_config()
        
        # 初始化向量数据库
        self.embeddings = OpenAIEmbeddings(openai_api_key=self.config.get("openai_api_key"))
        self.vector_store = Chroma(
            persist_directory=str(self.vector_db_dir),
            embedding_function=self.embeddings
        )
        
        # 初始化 LLM
        self.llm = ChatOpenAI(
            model_name="gpt-3.5-turbo-16k",
            temperature=0,
            openai_api_key=self.config.get("openai_api_key")
        )
        
        # 创建检索链
        self.retriever = self.vector_store.as_retriever(
            search_type="similarity",
            search_kwargs={"k": 5}
        )
        
        # 定义系统提示
        system_template = """你是一个专业的逆向工程知识助手。使用以下已检索的上下文片段来回答问题。
        如果你不知道答案，就说你不知道，不要试图编造信息。
        尽量使用上下文中的原始信息，并注明信息的来源。
        
        上下文信息:
        {context}
        
        请基于以上上下文，提供一个结构化和全面的回答。如果上下文中包含多个相关但不同的观点，请进行对比和总结。
        """
        
        messages = [
            SystemMessagePromptTemplate.from_template(system_template),
            HumanMessagePromptTemplate.from_template("{question}")
        ]
        
        prompt = ChatPromptTemplate.from_messages(messages)
        
        # 创建对话记忆
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            output_key="answer",  # 指定输出键
            return_messages=True
        )
        
        # 创建检索链
        self.qa_chain = ConversationalRetrievalChain.from_llm(
            llm=self.llm,
            retriever=self.retriever,
            memory=self.memory,
            return_source_documents=True,
            combine_docs_chain_kwargs={"prompt": prompt},
            chain_type="stuff",  # 指定链类型
            verbose=True  # 启用详细输出以便调试
        )

        # 创建命令补全器
        agent_commands = [
            'writeup', 'github', 'view', 'knowledge',
            'knowledge add', 'knowledge search', 'knowledge list', 
            'knowledge analyze', 'knowledge query', 'knowledge remove',
            'classify',  # 添加 classify 命令
            'help', 'exit', 'quit', 'back'
        ]

    def load_config(self):
        """加载配置"""
        config_file = self.config_dir / "agent_config.yaml"
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                'writeup': {
                    'template_version': '1.0',
                    'pdf_engine': 'pandoc',
                    'default_template': 'standard'
                },
                'github': {
                    'topics': ['reverse-engineering', 'binary-analysis', 
                             'malware-analysis', 'ida-pro', 'ghidra'],
                    'update_interval': 24, # hours
                    'min_stars': 50
                },
                'knowledge': {
                    'categories': [
                        'techniques', 'tools', 'vulnerabilities',
                        'papers', 'experiences', 'tutorials'
                    ]
                }
            }
            self.save_config()

    def save_config(self):
        """保存配置"""
        config_file = self.config_dir / "agent_config.yaml"
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, allow_unicode=True)

    def generate_writeup(self, title: str, template: str = 'standard'):
        """生成逆向分析报告模板"""
        try:
            template_file = self.templates_dir / f"{template}_writeup.md"
            if not template_file.exists():
                # 如果模板不存在，创建默认模板
                self._create_default_template(template_file)
            
            # 生成报告文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.reports_dir / f"writeup_{timestamp}_{title}.md"
            
            # 读取模板并替换变量
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            report_content = template_content.format(
                title=title,
                date=datetime.now().strftime("%Y-%m-%d"),
                author="Researcher"
            )
            
            # 保存报告
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            self.console.print(f"[green]Write-up template generated: {report_file}[/green]")
            return report_file
            
        except Exception as e:
            self.console.print(f"[red]Error generating write-up: {str(e)}[/red]")
            return None

    def _create_default_template(self, template_file: Path):
        """创建默认的写作模板"""
        template = """# {title}

## Basic Information

- **Date**: {date}
- **Author**: {author}
- **Target**: [Software Name and Version]
- **Platform**: [OS/Architecture]
- **Tools**: [List of Tools Used]

## Executive Summary

[Brief overview of the analysis and key findings]

## Technical Analysis

### 1. Initial Assessment
- File Properties
- Static Analysis Results
- Initial Behavioral Analysis

### 2. Dynamic Analysis
- Runtime Behavior
- Network Communications
- System Interactions

### 3. Code Analysis
- Key Functions
- Important Algorithms
- Protection Mechanisms

### 4. Vulnerabilities/Findings
- Detailed Description
- Technical Impact
- Exploitation Details

## Conclusion

[Summary of findings and implications]

## Recommendations

[Security recommendations and mitigation strategies]

## References

- [Reference 1]
- [Reference 2]

## Appendix

### A. Technical Details
[Additional technical information]

### B. Tools and Commands
[Specific tools and commands used]

### C. IOCs
[Indicators of Compromise if applicable]
"""
        with open(template_file, 'w', encoding='utf-8') as f:
            f.write(template)

    def monitor_github(self):
        """监控 GitHub 上的新逆向工程项目"""
        try:
            topics = self.config['github']['topics']
            min_stars = self.config['github']['min_stars']
            
            projects = []
            for topic in topics:
                response = httpx.get(
                    f"https://api.github.com/search/repositories",
                    params={
                        "q": f"topic:{topic} stars:>={min_stars}",
                        "sort": "updated",
                        "order": "desc"
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for repo in data['items'][:5]:  # 每个主题取前5个
                        projects.append({
                            'name': repo['name'],
                            'description': repo['description'],
                            'url': repo['html_url'],
                            'stars': repo['stargazers_count'],
                            'updated_at': repo['updated_at'],
                            'topics': repo['topics']
                        })
            
            # 生成推荐报告
            self._generate_github_report(projects)
            
        except Exception as e:
            self.console.print(f"[red]Error monitoring GitHub: {str(e)}[/red]")

    def _generate_github_report(self, projects: list):
        """生成 GitHub 项目推荐报告"""
        timestamp = datetime.now().strftime("%Y%m%d")
        report_file = self.reports_dir / f"github_report_{timestamp}.md"
        
        content = f"# Reverse Engineering Projects Daily Report\n\nDate: {datetime.now().strftime('%Y-%m-%d')}\n\n"
        
        for project in projects:
            content += f"## {project['name']}\n\n"
            content += f"- **Description**: {project['description']}\n"
            content += f"- **URL**: {project['url']}\n"
            content += f"- **Stars**: {project['stars']}\n"
            content += f"- **Topics**: {', '.join(project['topics'])}\n"
            content += f"- **Last Updated**: {project['updated_at']}\n\n"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        self.console.print(f"[green]GitHub report generated: {report_file}[/green]")

    def manage_knowledge(self, action: str, *args):
        """管理知识库"""
        try:
            if action == "add":
                if len(args) >= 2:
                    category = args[0]
                    title = args[1]
                    content = args[2] if len(args) > 2 else None
                    self.add_knowledge(category=category, title=title, content=content)
                else:
                    self.add_knowledge()  # 无参数时进入交互模式
            elif action == "search":
                self.search_knowledge(args[0] if args else None)
            elif action == "list":
                self.list_knowledge(args[0] if args else None)
            elif action == "analyze":
                self.analyze_knowledge(*args)
            elif action == "remove":
                self.remove_knowledge(*args)
            elif action == "query":
                self.query_knowledge(*args)
            elif action == "clear":
                self.clear_knowledge(*args)
            elif action == "status":
                self._show_knowledge_status()
            else:
                self.console.print("[red]Invalid knowledge management action[/red]")
        except Exception as e:
            self.console.print(f"[red]Error in knowledge management: {str(e)}[/red]")

    def add_knowledge(self, category: str = None, title: str = None, content: str = None):
        """添加知识到知识库"""
        try:
            self.console.print("[cyan]Adding new knowledge entry...[/cyan]")
            
            # 如果没有提供参数，进入交互模式
            if not category:
                self.console.print("[yellow]Entering interactive mode...[/yellow]")
                path = self.console.input("[cyan]Enter path to knowledge file/directory: [/cyan]")
                if not path:
                    self.console.print("[red]No path provided[/red]")
                    return False
                return self._process_knowledge_path(path)

            # 验证类别
            if category not in self.config['knowledge']['categories']:
                self.console.print(f"[red]Invalid category. Available categories: {', '.join(self.config['knowledge']['categories'])}[/red]")
                return False

            # 显示进度
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Creating knowledge entry...", total=None)
                
                # 创建知识文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{timestamp}_{title.lower().replace(' ', '-')}.md"
                file_path = self.knowledge_dir / category / filename

                # 确保目录存在
                file_path.parent.mkdir(parents=True, exist_ok=True)

                # 如果提供了内容源（文件或URL），处理它
                if content:
                    progress.update(task, description="Processing content source...")
                    content_path = Path(content)
                    
                    if content_path.exists():  # 是文件路径
                        # 根据文件类型选择合适的加载器
                        loader = self._get_document_loader(content_path)
                        if loader:
                            # 加载文档
                            progress.update(task, description=f"Loading {content_path.name}...")
                            documents = loader.load()
                            
                            # 合并文档内容
                            content = self._merge_documents(documents, title)
                            
                            # 保存原始文件
                            raw_file_path = self.raw_data_dir / category / content_path.name
                            raw_file_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(content_path, raw_file_path)
                        else:
                            self.console.print(f"[yellow]Unsupported file type: {content_path.suffix}[/yellow]")
                            return False
                            
                    elif content.startswith(('http://', 'https://')):  # 是URL
                        content = self._fetch_url_content(content)
                    # 文件夹，遍历文件夹下的所有文件，并添加到知识库
                    elif content_path.is_dir():
                        combined_content = []
                        for file in content_path.glob("**/*"):
                            if file.is_file():
                                loader = self._get_document_loader(file)
                                if loader:
                                    try:
                                        documents = loader.load()
                                        combined_content.append(self._merge_documents(documents, file.name))
                                    except Exception as e:
                                        self.console.print(f"[yellow]Warning: Could not process {file.name}: {str(e)}[/yellow]")
                        content = "\n\n".join(combined_content)
                else:
                    # 如果没有提供内容，创建一个模板
                    content = f"""# {title}

## Description

## Details

## References

*Added on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

                # 写入文件
                progress.update(task, description="Writing knowledge file...")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # 向量化并存储
                progress.update(task, description="Vectorizing content...")
                self._vectorize_and_store(
                    content=content,
                    metadata={
                        'title': title,
                        'category': category,
                        'source': str(file_path),
                        'date_added': datetime.now().isoformat()
                    }
                )

                progress.update(task, description="Finalizing...", completed=100)

            self.console.print(f"[green]Successfully added knowledge: {title}[/green]")
            self.console.print(f"[dim]File created: {file_path}[/dim]")
            
            # 显示更新后的知识库状态
            self._show_knowledge_status()
            return True

        except Exception as e:
            self.console.print(f"[red]Error adding knowledge: {str(e)}[/red]")
            return False

    def _get_document_loader(self, file_path: Path):
        """根据文件类型获取合适的文档加载器"""
        try:
            extension = file_path.suffix.lower()
            
            if extension == '.pdf':
                # 使用 PyMuPDF (fitz) 处理 PDF
                doc = fitz.open(str(file_path))
                text_content = ""
                for page in doc:
                    text_content += page.get_text()
                doc.close()
                
                # 创建一个简单的文档对象
                class Document:
                    def __init__(self, content, metadata=None):
                        self.page_content = content
                        self.metadata = metadata or {}
                
                # 返回包含文档内容的列表
                return type('PDFLoader', (), {
                    'load': lambda: [Document(
                        text_content,
                        {
                            'source': str(file_path),
                            'title': file_path.stem,
                            'type': 'pdf'
                        }
                    )]
                })
            
            # 其他文件类型的处理器
            loaders = {
                '.txt': TextLoader,
                '.md': UnstructuredMarkdownLoader,
                '.csv': CSVLoader,
                '.html': UnstructuredHTMLLoader,
                '.htm': UnstructuredHTMLLoader,
                '.doc': UnstructuredWordDocumentLoader,
                '.docx': UnstructuredWordDocumentLoader,
                '.ppt': UnstructuredPowerPointLoader,
                '.pptx': UnstructuredPowerPointLoader,
                '.epub': UnstructuredEPubLoader,
            }
            
            loader_class = loaders.get(extension)
            if loader_class:
                return loader_class(str(file_path))
            
            return None
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not create loader for {file_path.name}: {str(e)}[/yellow]")
            return None

    def _merge_documents(self, documents: list, title: str) -> str:
        """合并文档内容"""
        content = [f"# {title}\n"]
        
        # 添加元数据（如果有）
        if hasattr(documents[0], 'metadata'):
            metadata = documents[0].metadata
            if metadata.get('author'):
                content.append(f"Author: {metadata['author']}")
            if metadata.get('date'):
                content.append(f"Date: {metadata['date']}")
            content.append("")
        
        # 添加文档内容
        for doc in documents:
            content.append(doc.page_content)
        
        return "\n".join(content)

    def _extract_pdf_content(self, pdf_path: Path) -> str:
        """从 PDF 文件中提取文本内容"""
        try:
            text_content = []
            doc = fitz.open(pdf_path)
            
            # 提取标题（如果有）
            title = doc.metadata.get('title', pdf_path.stem)
            text_content.append(f"# {title}\n")
            
            # 提取作者信息（如果有）
            author = doc.metadata.get('author')
            if author:
                text_content.append(f"Author: {author}\n")
            
            # 提取每页内容
            for page_num in range(len(doc)):
                page = doc[page_num]
                text_content.append(f"\n## Page {page_num + 1}\n")
                text_content.append(page.get_text())
            
            doc.close()
            return "\n".join(text_content)
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Error extracting PDF content: {str(e)}[/yellow]")
            return f"Error extracting content from PDF: {pdf_path.name}"

    def _save_config(self):
        """保存配置到文件"""
        try:
            config_path = self.config_dir / 'config.json'
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.console.print(f"[red]Error saving config: {str(e)}[/red]")

    def query_knowledge(self, query: str, top_k: int = 5):
        """直接的语义搜索（不使用 LLM 总结）"""
        try:
            # 从向量数据库检索相关文档
            docs = self.vector_store.similarity_search(query, k=top_k)
            
            # 创建结果表格
            table = Table(title=f"Direct Search Results for: {query}")
            table.add_column("Title", style="cyan")
            table.add_column("Category", style="green")
            table.add_column("Content Preview", style="white")
            table.add_column("Date", style="yellow")
            
            for doc in docs:
                metadata = doc.metadata
                preview = doc.page_content[:200] + "..."
                
                table.add_row(
                    metadata.get("title", "Unknown"),
                    metadata.get("category", "Unknown"),
                    preview,
                    metadata.get("date", "Unknown")
                )
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error querying knowledge base: {str(e)}[/red]")

    def search_knowledge(self, query: str = None):
        """搜索知识库并使用LLM生成智能总结"""
        try:
            if not query:
                query = self.console.input("[cyan]Enter search query: [/cyan]")
                if not query:
                    self.console.print("[red]Search cancelled - no query provided[/red]")
                    return False

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                # 首先尝试向量搜索
                progress.add_task("Searching knowledge base...", total=None)
                try:
                    docs = self.vector_store.similarity_search_with_score(
                        query,
                        k=5  # 返回前5个最相关的结果
                    )
                except Exception as e:
                    self.console.print(f"[yellow]Warning: Vector search failed: {str(e)}[/yellow]")
                    self.console.print("[yellow]Falling back to basic search...[/yellow]")
                    docs = self._fallback_search(query)

            if not docs:
                self.console.print("[yellow]No matching documents found[/yellow]")
                return False

            # 使用LLM生成总结
            progress.add_task("Generating summary...", total=None)
            summary = self._generate_summary(query, docs)
            
            # 显示LLM总结
            self.console.print("\n[bold cyan]Summary[/bold cyan]")
            self.console.print(Panel(Markdown(summary), title="AI Analysis", border_style="cyan"))

            # 显示搜索结果
            table = Table(title="Search Results")
            table.add_column("Category", style="cyan")
            table.add_column("Title", style="green")
            table.add_column("Preview", style="white")

            for doc, score in docs:
                metadata = doc.metadata
                preview = doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
                
                table.add_row(
                    metadata.get('category', 'Unknown'),
                    metadata.get('title', 'Untitled'),
                    preview
                )

            self.console.print("\n[bold cyan]Detailed Results[/bold cyan]")
            self.console.print(table)

            # 询问是否查看完整内容
            while True:
                choice = self.console.input("\n[cyan]Enter number to view full content (or 'q' to quit): [/cyan]")
                if choice.lower() == 'q':
                    break
                
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(docs):
                        doc = docs[idx][0]  # 获取文档对象
                        self.console.print("\n[bold cyan]Full Content:[/bold cyan]")
                        self.console.print(Markdown(doc.page_content))
                        
                        # 显示文件位置
                        if 'source' in doc.metadata:
                            self.console.print(f"\n[dim]Source: {doc.metadata['source']}[/dim]")
                    else:
                        self.console.print("[red]Invalid number[/red]")
                except ValueError:
                    self.console.print("[red]Invalid input[/red]")

            return True

        except Exception as e:
            self.console.print(f"[red]Error searching knowledge base: {str(e)}[/red]")
            return False

    def _generate_summary(self, query: str, docs: list) -> str:
        """使用LLM生成搜索结果总结"""
        try:
            # 准备文档内容
            context = []
            for i, (doc, score) in enumerate(docs[:3], 1):  # 只使用前3个最相关的文档
                context.append(
                    f"Document {i}:\n"
                    f"Title: {doc.metadata.get('title', 'Untitled')}\n"
                    f"Category: {doc.metadata.get('category', 'Unknown')}\n"
                    f"Content: {doc.page_content}\n"
                )

            # 构建提示
            prompt = (
                f'基于以下文档，请对这个查询提供全面的回答: "{query}"\n\n'
                '请遵循以下指南：\n'
                '1. 从文档中提取并引用3个最相关的段落\n'
                '2. 提供关键要点的简明总结\n'
                '3. 突出显示重要的技术细节\n'
                '4. 指出文档之间的任何信息冲突\n'
                '5. 使用markdown格式输出\n\n'
                '文档内容：\n'
                f'{chr(10).join(context)}\n\n'
                '请按以下结构组织回答：\n'
                '1. 关键引用（附带文档来源）\n'
                '2. 总结分析\n'
                '3. 技术细节（如果有）\n'
                '4. 补充说明（如果有）'
            )

            messages = [
                SystemMessage(content="You are a reverse engineering knowledge expert."),
                HumanMessage(content=prompt)
            ]

            # 获取LLM响应
            response = self.llm.invoke(messages).content
            return response

        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not generate summary: {str(e)}[/yellow]")
            return "Error generating summary. Please check the detailed results below."

    def _fallback_search(self, query: str, max_results: int = 5):
        """基本的文本搜索作为备选方案"""
        try:
            results = []
            query = query.lower()
            
            # 遍历所有知识文件
            for category in self.config['knowledge']['categories']:
                category_dir = self.knowledge_dir / category
                if category_dir.exists():
                    for file_path in category_dir.glob("*.md"):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                            # 简单的相关性评分
                            score = self._calculate_relevance(content.lower(), query)
                            
                            if score > 0:
                                doc = type('Document', (), {
                                    'page_content': content,
                                    'metadata': {
                                        'category': category,
                                        'title': file_path.stem,
                                        'source': str(file_path)
                                    }
                                })
                                results.append((doc, score))
                        except Exception as e:
                            self.console.print(f"[yellow]Warning: Could not process {file_path}: {str(e)}[/yellow]")
                            continue
            
            # 按相关性排序
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:max_results]
            
        except Exception as e:
            self.console.print(f"[yellow]Warning: Fallback search failed: {str(e)}[/yellow]")
            return []

    def _calculate_relevance(self, content: str, query: str) -> float:
        """计算文本相关性分数"""
        try:
            # 简单的词频计算
            query_terms = query.split()
            score = 0
            
            for term in query_terms:
                score += content.count(term)
                
            # 标题匹配给予更高权重
            first_line = content.split('\n')[0].lower()
            for term in query_terms:
                if term in first_line:
                    score += 5
                    
            return score
            
        except Exception:
            return 0

    def list_knowledge(self, category: str = None):
        """列出知识库内容"""
        try:
            categories = [category] if category else self.config['knowledge']['categories']
            
            table = Table(title="Knowledge Base Contents")
            table.add_column("Category")
            table.add_column("Title")
            table.add_column("Date")
            
            for cat in categories:
                category_dir = self.knowledge_dir / cat
                if category_dir.exists():
                    for file in category_dir.glob("*.md"):
                        with open(file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            title = content.split('\n')[0].strip('# ')
                            date = file.stem.split('_')[0]
                            table.add_row(cat, title, date)
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error listing knowledge: {str(e)}[/red]")

    def analyze_knowledge(self, category: str = None):
        """分析知识库内容"""
        try:
            categories = [category] if category else self.config['knowledge']['categories']
            analysis = {
                'total_entries': 0,
                'entries_by_category': {},
                'recent_entries': []
            }
            
            for cat in categories:
                category_dir = self.knowledge_dir / cat
                if category_dir.exists():
                    files = list(category_dir.glob("*.md"))
                    analysis['entries_by_category'][cat] = len(files)
                    analysis['total_entries'] += len(files)
                    
                    # 获取最近的条目
                    for file in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
                        with open(file, 'r', encoding='utf-8') as f:
                            title = f.readline().strip('# \n')
                            analysis['recent_entries'].append({
                                'category': cat,
                                'title': title,
                                'file': file.name
                            })
            
            # 显示分析结果
            self.console.print("\n[bold cyan]Knowledge Base Analysis[/bold cyan]")
            self.console.print(f"\nTotal Entries: {analysis['total_entries']}")
            
            # 显示分类统计
            table = Table(title="Entries by Category")
            table.add_column("Category")
            table.add_column("Count")
            
            for cat, count in analysis['entries_by_category'].items():
                table.add_row(cat, str(count))
            
            self.console.print(table)
            
            # 显示最近条目
            self.console.print("\n[bold]Recent Entries:[/bold]")
            for entry in analysis['recent_entries']:
                self.console.print(f"- [{entry['category']}] {entry['title']}")
            
        except Exception as e:
            self.console.print(f"[red]Error analyzing knowledge: {str(e)}[/red]")

    def view_github_report(self, date: str = None):
        """查看 GitHub 推荐项目报告"""
        try:
            # 如果没有指定日期，使用今天的日期
            if not date:
                date = datetime.now().strftime("%Y%m%d")
            
            report_file = self.reports_dir / f"github_report_{date}.md"
            
            if not report_file.exists():
                self.console.print(f"[yellow]No report found for date: {date}[/yellow]")
                # 列出可用的报告
                reports = list(self.reports_dir.glob("github_report_*.md"))
                if reports:
                    self.console.print("\n[cyan]Available reports:[/cyan]")
                    for report in sorted(reports, reverse=True)[:5]:
                        report_date = report.stem.split('_')[-1]
                        self.console.print(f"- {report_date}")
                return
            
            # 读取并显示报告内容
            with open(report_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 解析内容并创建表格显示
            projects = []
            current_project = None
            
            for line in content.split('\n'):
                if line.startswith('## '):
                    if current_project:
                        projects.append(current_project)
                    current_project = {'name': line[3:].strip()}
                elif line.startswith('- **') and current_project:
                    key, value = line[4:].split('**: ', 1)
                    current_project[key.lower()] = value.strip()
            
            if current_project:
                projects.append(current_project)
            
            # 创建表格显示
            table = Table(
                title=f"GitHub Reverse Engineering Projects ({date})",
                show_lines=True,
                width=100
            )
            
            table.add_column("Project", style="cyan", width=20)
            table.add_column("Description", width=40)
            table.add_column("Stars", justify="right", width=10)
            table.add_column("Topics", width=30)
            
            for project in projects:
                table.add_row(
                    project.get('name', ''),
                    project.get('description', ''),
                    str(project.get('stars', '')),
                    project.get('topics', '')
                )
            
            self.console.print(table)
            
            # 显示详细链接
            self.console.print("\n[bold cyan]Project URLs:[/bold cyan]")
            for project in projects:
                self.console.print(f"[bold]{project.get('name')}[/bold]: {project.get('url', '')}")
            
        except Exception as e:
            self.console.print(f"[red]Error viewing GitHub report: {str(e)}[/red]")

    def handle_command(self, command: str, *args):
        """处理命令"""
        try:
            parts = command.split()
            main_command = parts[0].lower()
            command_args = parts[1:] if len(parts) > 1 else []

            if main_command == "writeup":
                if len(command_args) >= 1:
                    self.generate_writeup(command_args[0])
                else:
                    self.console.print("[red]Please provide a title for the write-up[/red]")
            
            elif main_command == "github":
                self.monitor_github()
            
            elif main_command == "view":
                if len(command_args) >= 1:
                    self.view_github_report(command_args[0])
                else:
                    self.view_github_report()
            
            elif main_command == "classify":
                if len(command_args) >= 1:
                    self.classify_files(command_args[0])
                else:
                    self.console.print("[red]Usage: classify <folder_path>[/red]")
                    self.console.print("[yellow]Example: classify ./docs[/yellow]")
                    self.console.print("\nThis command will:")
                    self.console.print("1. Analyze all files in the specified folder")
                    self.console.print("2. Suggest appropriate categories")
                    self.console.print("3. Create category folders")
                    self.console.print("4. Move files to their respective categories")
            
            elif main_command == "knowledge":
                if len(command_args) >= 1:
                    action = command_args[0]
                    if action == "add":
                        if len(command_args) < 3:
                            self.console.print("[red]Usage: knowledge add <category> <title> [file/url][/red]")
                            return
                        
                        category = command_args[1]
                        title = command_args[2]
                        content = command_args[3] if len(command_args) > 3 else None
                        # 添加知识, 如果content为空，则提示用户输入内容，可以是文档或url或文件路径
                        if content is None:
                            self.console.print("[yellow]Please provide content for the knowledge entry.[/yellow]")
                            content = self.console.input("[cyan]Content: [/cyan]")
                        self.add_knowledge(category, title, content)
                    elif action == "query":
                        if len(command_args) < 2:
                            self.console.print("[red]Usage: knowledge query <search_text>[/red]")
                            return
                        query = ' '.join(command_args[1:])
                        self.query_knowledge(query)
                    
                    elif action == "remove":
                        if len(command_args) < 2:
                            self.console.print("[red]Usage: knowledge remove <category> <title>[/red]")
                            return
                        category = command_args[1]
                        title = ' '.join(command_args[2:])
                        self.remove_knowledge(category, title)
                    
                    else:
                        self.manage_knowledge(*command_args)
                else:
                    self.console.print("[red]Please specify a knowledge management action[/red]")
            
            else:
                self.console.print("[red]Unknown command[/red]")
                
        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")

    def remove_knowledge(self, category: str, title: str):
        """移除指定的知识库条目"""
        try:
            category_dir = self.knowledge_dir / category
            raw_category_dir = self.raw_data_dir / category
            
            # 获取匹配的文件
            matching_files = list(category_dir.glob(f"*{title}*.md"))
            if not matching_files:
                self.console.print(f"[yellow]No matching entries found for category '{category}' and title '{title}'[/yellow]")
                return
            
            # 显示匹配的条目
            table = Table(title="Matching Entries")
            table.add_column("File", style="cyan")
            table.add_column("Category", style="green")
            table.add_column("Title", style="yellow")
            table.add_column("Date", style="magenta")
            
            for file in matching_files:
                with open(file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    title = content.split('\n')[0].strip('# ')
                    date = file.stem.split('_')[0]
                    table.add_row(file.name, category, title, date)
            
            self.console.print(table)
            
            # 确认是否移除
            confirm = self.console.input("\n[yellow]Do you want to remove these entries? (y/N): [/yellow]")
            if confirm.lower() != 'y':
                self.console.print("[yellow]Removal cancelled[/yellow]")
                return
            
            # 移除文件
            for file in matching_files:
                try:
                    file.unlink()
                    self.console.print(f"[green]Removed: {file}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error removing {file}: {str(e)}[/red]")
            
            # 移除原始数据文件
            for file in raw_category_dir.glob(f"*{title}*"):
                try:
                    file.unlink()
                    self.console.print(f"[green]Removed raw data: {file}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error removing raw data {file}: {str(e)}[/red]")
            
            # 更新向量数据库
            self._update_vector_db_after_removal(category, title)
            
        except Exception as e:
            self.console.print(f"[red]Error removing knowledge: {str(e)}[/red]")

    def _update_vector_db_after_removal(self, category: str, title: str):
        """更新向量数据库（移除条目后）"""
        try:
            # 使用 Chroma 的 _collection 来获取所有文档
            collection = self.vector_store._collection
            
            # 获取所有文档
            results = collection.get(
                include=['documents', 'metadatas', 'ids']
            )
            
            if results['ids']:
                # 过滤出需要保留的文档
                filtered_indices = []
                for i, metadata in enumerate(results['metadatas']):
                    # 保留不匹配的文档
                    if (metadata.get('category') != category or 
                        not metadata.get('title', '').startswith(title)):
                        filtered_indices.append(i)
                
                if filtered_indices:
                    # 提取需要保留的文档
                    filtered_docs = [results['documents'][i] for i in filtered_indices]
                    filtered_meta = [results['metadatas'][i] for i in filtered_indices]
                    filtered_ids = [results['ids'][i] for i in filtered_indices]
                    
                    # 删除所有现有文档
                    self.vector_store.delete(ids=None)
                    
                    # 重新添加过滤后的文档
                    self.vector_store.add_texts(
                        texts=filtered_docs,
                        metadatas=filtered_meta,
                        ids=filtered_ids
                    )
                    
                    self.console.print("[green]Vector database updated after removal[/green]")
                else:
                    # 如果没有需要保留的文档，清空数据库
                    self.vector_store.delete(ids=None)
                    self.console.print("[yellow]All documents removed from vector database[/yellow]")
            else:
                self.console.print("[yellow]No documents found in vector database[/yellow]")
            
        except Exception as e:
            self.console.print(f"[red]Error updating vector database after removal: {str(e)}[/red]")

    def classify_files(self, folder_path: str):
        """智能分类指定文件夹中的文件"""
        try:
            folder = Path(folder_path)
            if not folder.exists() or not folder.is_dir():
                self.console.print(f"[red]Invalid folder path: {folder_path}[/red]")
                return False

            # 获取文件列表
            files = list(folder.glob('*'))
            if not files:
                self.console.print("[yellow]No files found in the specified folder[/yellow]")
                return False

            # 准备文件信息
            file_info = []
            for file in files:
                if file.is_file():
                    # 获取文件基本信息
                    info = {
                        'name': file.name,
                        'extension': file.suffix.lower(),
                        'size': file.stat().st_size,
                        'preview': self._get_file_preview(file)
                    }
                    file_info.append(info)

            # 构建 LLM 提示
            prompt = self._build_classification_prompt(file_info)
            
            # 调用 LLM 进行分类
            self.console.print("[cyan]Analyzing files...[/cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                progress.add_task("Classifying files...", total=None)
                classification_result = self._get_classification_from_llm(prompt)

            # 显示分类建议
            self._display_classification_suggestion(classification_result, file_info)

            # 询问用户是否接受分类建议
            confirm = self.console.input("\n[yellow]Do you want to apply this classification? (y/N): [/yellow]")
            if confirm.lower() == 'y':
                self._apply_classification(folder, classification_result)
                self.console.print("[green]Classification completed successfully![/green]")
                return True
            else:
                self.console.print("[yellow]Classification cancelled[/yellow]")
                return False

        except Exception as e:
            self.console.print(f"[red]Error during classification: {str(e)}[/red]")
            return False

    def _get_file_preview(self, file_path: Path, max_size: int = 1024) -> str:
        """获取文件预览内容"""
        try:
            if file_path.suffix.lower() in ['.pdf']:
                # 处理 PDF 文件
                doc = fitz.open(file_path)
                preview = doc[0].get_text()[:max_size]
                doc.close()
            elif file_path.suffix.lower() in ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml']:
                # 处理文本文件
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    preview = f.read(max_size)
            else:
                # 其他文件类型
                preview = f"Binary file ({file_path.suffix})"
            return preview
        except Exception:
            return f"Unable to preview file ({file_path.suffix})"

    def _build_classification_prompt(self, file_info: list) -> str:
        """构建分类提示"""
        prompt = """Please analyze the following files and suggest a classification scheme. 
For each file, provide:
1. Suggested category
2. Reason for classification
3. Confidence level (high/medium/low)

Consider the following aspects:
- File content and context
- File type and extension
- Common reverse engineering categories
- Potential security implications

Files to analyze:

"""
        for info in file_info:
            prompt += f"\nFile: {info['name']}\n"
            prompt += f"Type: {info['extension']}\n"
            prompt += f"Size: {info['size']} bytes\n"
            prompt += f"Preview: {info['preview'][:200]}...\n"
            prompt += "-" * 40 + "\n"

        return prompt

    def _get_classification_from_llm(self, prompt: str) -> dict:
        """从 LLM 获取分类建议"""
        try:
            messages = [
                SystemMessage(content="You are a reverse engineering file classification expert."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages).content

            # 解析 LLM 响应
            classification = {}
            current_file = None
            
            for line in response.split('\n'):
                if line.startswith('File:'):
                    current_file = line.split('File:')[1].strip()
                    classification[current_file] = {}
                elif current_file and line.startswith('Category:'):
                    classification[current_file]['category'] = line.split('Category:')[1].strip()
                elif current_file and line.startswith('Reason:'):
                    classification[current_file]['reason'] = line.split('Reason:')[1].strip()
                elif current_file and line.startswith('Confidence:'):
                    classification[current_file]['confidence'] = line.split('Confidence:')[1].strip()

            return classification

        except Exception as e:
            self.console.print(f"[red]Error getting classification from LLM: {str(e)}[/red]")
            return {}

    def _display_classification_suggestion(self, classification: dict, file_info: list):
        """显示分类建议"""
        table = Table(title="File Classification Suggestion")
        table.add_column("File", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Reason", style="yellow")
        table.add_column("Confidence", style="magenta")

        for info in file_info:
            file_name = info['name']
            if file_name in classification:
                c = classification[file_name]
                table.add_row(
                    file_name,
                    c.get('category', 'Unknown'),
                    c.get('reason', 'N/A'),
                    c.get('confidence', 'N/A')
                )

        self.console.print(table)

    def _apply_classification(self, base_folder: Path, classification: dict):
        """应用分类结果"""
        # 收集所有唯一的类别
        categories = set()
        for file_info in classification.values():
            categories.add(file_info['category'])

        # 创建类别文件夹
        for category in categories:
            category_dir = base_folder / category
            category_dir.mkdir(exist_ok=True)

        # 移动文件到对应的类别文件夹
        for file_name, file_info in classification.items():
            source = base_folder / file_name
            if source.exists():
                target = base_folder / file_info['category'] / file_name
                try:
                    source.rename(target)
                    self.console.print(f"[green]Moved {file_name} to {file_info['category']}[/green]")
                except Exception as e:
                    self.console.print(f"[red]Error moving {file_name}: {str(e)}[/red]")

    def import_documents(self, source_path: Union[str, Path], category: str = None):
        """导入并向量化文档"""
        try:
            source_path = Path(source_path)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task("Processing documents...", total=None)
                
                if source_path.is_file():
                    # 处理单个文件
                    self._process_single_file(source_path, category)
                elif source_path.is_dir():
                    # 处理目录中的所有文件
                    self._process_directory(source_path, category)
                else:
                    self.console.print(f"[red]Invalid path: {source_path}[/red]")
                    return False
                
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error importing documents: {str(e)}[/red]")
            return False

    def _process_directory(self, dir_path: Path, category: str = None):
        """处理目录中的所有支持的文件"""
        supported_extensions = {
            '.txt': self._process_text_file,
            '.pdf': self._process_pdf_file,
            '.csv': self._process_csv_file,
            '.md': self._process_text_file,
            '.json': self._process_text_file,
            '.xml': self._process_text_file,
            '.html': self._process_text_file
        }
        
        # 统计处理结果
        results = {
            'success': 0,
            'failed': 0,
            'skipped': 0
        }
        
        for file_path in dir_path.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in supported_extensions:
                try:
                    processor = supported_extensions[file_path.suffix.lower()]
                    if processor(file_path, category):
                        results['success'] += 1
                    else:
                        results['failed'] += 1
                except Exception as e:
                    self.console.print(f"[red]Error processing {file_path}: {str(e)}[/red]")
                    results['failed'] += 1
            else:
                results['skipped'] += 1
        
        # 显示处理结果
        table = Table(title="Document Processing Results")
        table.add_column("Status", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Successfully processed", str(results['success']))
        table.add_row("Failed to process", str(results['failed']))
        table.add_row("Skipped files", str(results['skipped']))
        
        self.console.print(table)

    def _process_single_file(self, file_path: Path, category: str = None):
        """处理单个文件"""
        processors = {
            '.txt': self._process_text_file,
            '.pdf': self._process_pdf_file,
            '.csv': self._process_csv_file,
            '.md': self._process_text_file,
            '.json': self._process_text_file,
            '.xml': self._process_text_file,
            '.html': self._process_text_file
        }
        
        extension = file_path.suffix.lower()
        if extension in processors:
            return processors[extension](file_path, category)
        else:
            self.console.print(f"[yellow]Unsupported file type: {extension}[/yellow]")
            return False

    def _process_text_file(self, file_path: Path, category: str = None) -> bool:
        """处理文本文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 保存原始文件
            dest_path = self.raw_data_dir / category if category else self.raw_data_dir
            dest_path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest_path / file_path.name)
            
            # 向量化并存储
            return self._vectorize_and_store(
                content=content,
                metadata={
                    'title': file_path.stem,
                    'category': category or 'general',
                    'source_type': 'text',
                    'original_file': str(file_path),
                    'date_added': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            self.console.print(f"[red]Error processing text file {file_path}: {str(e)}[/red]")
            return False

    def _process_pdf_file(self, file_path: Path, category: str = None) -> bool:
        """处理PDF文件"""
        try:
            text_content = ""
            with fitz.open(file_path) as doc:
                for page in doc:
                    text_content += page.get_text()
            
            # 保存原始文件
            dest_path = self.raw_data_dir / category if category else self.raw_data_dir
            dest_path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest_path / file_path.name)
            
            # 向量化并存储
            return self._vectorize_and_store(
                content=text_content,
                metadata={
                    'title': file_path.stem,
                    'category': category or 'general',
                    'source_type': 'pdf',
                    'original_file': str(file_path),
                    'date_added': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            self.console.print(f"[red]Error processing PDF file {file_path}: {str(e)}[/red]")
            return False

    def _process_csv_file(self, file_path: Path, category: str = None) -> bool:
        """处理CSV文件"""
        try:
            import pandas as pd
            df = pd.read_csv(file_path)
            
            # 将CSV转换为文本格式
            text_content = df.to_string()
            
            # 保存原始文件
            dest_path = self.raw_data_dir / category if category else self.raw_data_dir
            dest_path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest_path / file_path.name)
            
            # 向量化并存储
            return self._vectorize_and_store(
                content=text_content,
                metadata={
                    'title': file_path.stem,
                    'category': category or 'general',
                    'source_type': 'csv',
                    'original_file': str(file_path),
                    'date_added': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            self.console.print(f"[red]Error processing CSV file {file_path}: {str(e)}[/red]")
            return False

    def _vectorize_and_store(self, content: str, metadata: dict) -> bool:
        """向量化并存储文档内容"""
        try:
            # 文本分割
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=200,
                length_function=len,
            )
            
            chunks = text_splitter.split_text(content)
            
            # 为每个块添加元数据和块ID
            docs = [{"page_content": chunk, "metadata": {**metadata, "chunk_id": i}} 
                   for i, chunk in enumerate(chunks)]
            
            # 添加到向量数据库
            self.vector_store.add_texts(
                texts=[doc["page_content"] for doc in docs],
                metadatas=[doc["metadata"] for doc in docs]
            )
            
            self.console.print(f"[green]Successfully vectorized and stored: {metadata['title']}[/green]")
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error vectorizing content: {str(e)}[/red]")
            return False

    def clear_knowledge(self, confirm: bool = False):
        """清理知识库，包括向量数据库和原始文件"""
        try:
            if not confirm:
                # 显示当前知识库状态
                self._show_knowledge_status()
                
                # 请求用户确认
                confirmation = self.console.input("\n[yellow]Are you sure you want to clear all knowledge? This action cannot be undone! (yes/N): [/yellow]")
                if confirmation.lower() != 'yes':
                    self.console.print("[yellow]Operation cancelled[/yellow]")
                    return False

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                # 清理向量数据库
                progress.add_task("Clearing vector database...", total=None)
                # 获取所有文档ID
                collection = self.vector_store._collection
                if collection.count() > 0:
                    all_ids = collection.get()['ids']
                    if all_ids:
                        self.vector_store.delete(ids=all_ids)
                
                # 清理原始文件目录
                progress.add_task("Clearing raw data...", total=None)
                if self.raw_data_dir.exists():
                    shutil.rmtree(self.raw_data_dir)
                    self.raw_data_dir.mkdir(parents=True)
                
                # 清理知识目录
                progress.add_task("Clearing knowledge files...", total=None)
                if self.knowledge_dir.exists():
                    shutil.rmtree(self.knowledge_dir)
                    self.knowledge_dir.mkdir(parents=True)
                
                # 重新创建必要的子目录
                for category in self.config['knowledge']['categories']:
                    (self.knowledge_dir / category).mkdir(exist_ok=True)
                    (self.raw_data_dir / category).mkdir(exist_ok=True)

            self.console.print("[green]Knowledge base cleared successfully![/green]")
            self.console.print("[cyan]The system is ready for new knowledge import.[/cyan]")
            return True

        except Exception as e:
            self.console.print(f"[red]Error clearing knowledge base: {str(e)}[/red]")
            return False

    def _show_knowledge_status(self):
        """显示当前知识库状态"""
        try:
            # 创建状态表格
            table = Table(title="Knowledge Base Status")
            table.add_column("Category", style="cyan")
            table.add_column("Files Count", justify="right", style="green")
            table.add_column("Raw Files", justify="right", style="yellow")
            table.add_column("Total Size", justify="right", style="magenta")
            
            total_files = 0
            total_raw_files = 0
            total_size = 0
            
            # 统计每个类别的文件
            for category in self.config['knowledge']['categories']:
                knowledge_path = self.knowledge_dir / category
                raw_path = self.raw_data_dir / category
                
                # 统计知识文件
                knowledge_files = list(knowledge_path.glob('*')) if knowledge_path.exists() else []
                knowledge_count = len(knowledge_files)
                total_files += knowledge_count
                
                # 统计原始文件
                raw_files = list(raw_path.glob('*')) if raw_path.exists() else []
                raw_count = len(raw_files)
                total_raw_files += raw_count
                
                # 计算总大小
                category_size = sum(f.stat().st_size for f in knowledge_files + raw_files)
                total_size += category_size
                
                # 格式化大小显示
                size_str = self._format_size(category_size)
                
                table.add_row(
                    category,
                    str(knowledge_count),
                    str(raw_count),
                    size_str
                )
            
            # 添加总计行
            table.add_row(
                "Total",
                str(total_files),
                str(total_raw_files),
                self._format_size(total_size),
                style="bold"
            )
            
            # 显示向量数据库信息
            collection = self.vector_store._collection
            vector_count = len(collection.get()['ids']) if collection.get()['ids'] else 0
            
            self.console.print("\n[bold cyan]Current Knowledge Base Status:[/bold cyan]")
            self.console.print(table)
            self.console.print(f"\nVector Database Entries: [yellow]{vector_count}[/yellow]")
            
        except Exception as e:
            self.console.print(f"[red]Error showing knowledge status: {str(e)}[/red]")

    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小显示"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def process_command(self, command: str):
        """处理命令"""
        try:
            if not command:
                return True
                
            if command == "exit":
                return False
            
            command_parts = command.strip().split()
            main_command = command_parts[0].lower()
            
            if main_command not in self.command_handlers:
                self.console.print(f"[red]Unknown command: '{main_command}'[/red]")
                self.console.print("Use 'help' to see available commands.")
                return True
            
            if main_command == "help":
                self.command_handlers[main_command]()
                return True
            
            if main_command == "knowledge":
                if len(command_parts) < 2:
                    self.console.print("[red]Missing knowledge sub-command. Use 'help' to see available commands.[/red]")
                    return True
                
                sub_command = command_parts[1].lower()
                if sub_command not in self.command_handlers[main_command]:
                    self.console.print(f"[red]Invalid knowledge sub-command: '{sub_command}'[/red]")
                    self.console.print("Available sub-commands: add, search, clear, status")
                    return True
                
                # 调用对应的处理函数
                handler = self.command_handlers[main_command][sub_command]
                if sub_command == 'search' and len(command_parts) > 2:
                    query = " ".join(command_parts[2:])
                    handler(query)
                elif sub_command == 'add' and len(command_parts) > 2:
                    # 将剩余的参数作为一个字符串传递
                    args = " ".join(command_parts[2:])
                    handler(args)
                else:
                    handler()
            
            return True
            
        except Exception as e:
            self.console.print(f"[red]Error processing command: {str(e)}[/red]")
            return True