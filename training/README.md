# ThreatClaw L0 — Fine-tuning Dataset

## Objectif

Fine-tuner Qwen3 8B en "ThreatClaw AI Ops" — le chatbot conversationnel du RSSI.

## Hardware requis

- **MacBook M3 Pro** avec MLX (recommandé) : `pip install mlx-lm`
- **RTX 3080** avec Unsloth : `pip install unsloth`

## Commande MLX (Mac)

```bash
mlx_lm.lora \
  --model mlx-community/Qwen2.5-7B-Instruct-4bit \
  --train \
  --data ./dataset \
  --batch-size 4 \
  --lora-layers 8 \
  --lora-rank 8 \
  --epochs 3 \
  --learning-rate 2e-4 \
  --output ./adapters
```

## Commande Unsloth (NVIDIA)

```python
from unsloth import FastLanguageModel
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
    max_seq_length=2048,
    load_in_4bit=True,
)
model = FastLanguageModel.get_peft_model(
    model, r=8, lora_alpha=16,
    target_modules=["q_proj","k_proj","v_proj","o_proj",
                     "gate_proj","up_proj","down_proj"],
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing="unsloth",
)
```

## Conversion pour Ollama

```bash
# Après training MLX
mlx_lm.fuse --model mlx-community/Qwen2.5-7B-Instruct-4bit --adapter-path ./adapters --output ./threatclaw-l0-fused

# Convertir en GGUF
python convert_hf_to_gguf.py ./threatclaw-l0-fused --outtype q4_k_m --outfile threatclaw-l0.gguf

# Créer Modelfile Ollama
echo 'FROM ./threatclaw-l0.gguf
PARAMETER temperature 0.7
PARAMETER num_predict 500
SYSTEM "Tu es ThreatClaw AI Ops, l assistant de securite de ThreatClaw."' > Modelfile.threatclaw-l0

ollama create threatclaw-l0 -f Modelfile.threatclaw-l0
```

## Structure du dataset

```
training/
├── README.md (ce fichier)
├── dataset/
│   ├── train.jsonl (900 paires — 90%)
│   └── valid.jsonl (100 paires — 10%)
└── Modelfile.threatclaw-l0
```
