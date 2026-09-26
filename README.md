# AgentXRay

AgentXRay leverages the OS-Harm Tasks and OSWorld Instrumentation. For initial setup, please refer to

OS-Harm: https://github.com/tml-epfl/os-harm

OSWorld: The Instrument of this benchmark is based on the OSWorld environment, you can follow OSWorld’s installation instructions to set it up and OSWorld’s FAQ or issues section in case of problem. https://github.com/xlang-ai/OSWorld/?tab=readme-ov-file#-installation

Below are the files we edited in OS-Harm for AgentXRay setup
```text
AgentXRay/
├── README.md
├── run.py
├── lib_run_single.py
│
├── judge/
│   ├── run_judge.py
│   └── methods/
│       ├── plain_judge.py
│       └── aseg_builder.py
│
└── evaluation/
    ├── annotations/
    └── task_lists/
```

