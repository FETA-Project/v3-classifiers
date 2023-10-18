from enum import Enum
from functools import partial
from typing import Optional

import torch
import torch.nn.functional as F
from cesnet_datazoo.constants import PPI_MAX_LEN
from torch import nn


class NormLayerEnum(Enum):
    BATCH_NORM = "batch-norm"
    LAYER_NORM = "layer-norm"
    INSTANCE_NORM = "instance-norm"
    NO_NORM = "no-norm"
    def __str__(self): return self.value

def conv_norm_layer(channels: int, normalization: NormLayerEnum):
    if normalization == NormLayerEnum.BATCH_NORM:
        return [nn.BatchNorm1d(channels)]
    elif normalization == NormLayerEnum.INSTANCE_NORM:
        return [nn.InstanceNorm1d(channels)]
    elif normalization == NormLayerEnum.NO_NORM:
        return []
    else:
        raise ValueError(f"Bad normalization for nn.Conv1d: {str(normalization)}")

def linear_norm_layer(size: int, normalization: NormLayerEnum):
    if normalization == NormLayerEnum.BATCH_NORM:
        return [nn.BatchNorm1d(size)]
    if normalization == NormLayerEnum.LAYER_NORM:
        return [nn.LayerNorm(size)]
    elif normalization == NormLayerEnum.NO_NORM:
        return []
    else:
        raise ValueError(f"Bad normalization for nn.Linear: {str(normalization)}")

class GeM(nn.Module):
    """
    https://www.kaggle.com/code/scaomath/g2net-1d-cnn-gem-pool-pytorch-train-inference
    """
    def __init__(self, kernel_size, p=3, eps=1e-6):
        super(GeM, self).__init__()
        self.p = nn.Parameter(torch.ones(1) * p) # type: ignore
        self.kernel_size = kernel_size
        self.eps = eps

    def forward(self, x):
        return self.gem(x, p=self.p, eps=self.eps) # type: ignore

    def gem(self, x, p=3, eps=1e-6):
        return F.avg_pool1d(x.clamp(min=eps).pow(p), self.kernel_size).pow(1./p)

    def __repr__(self):
        return self.__class__.__name__ + \
                "(" + "kernel_size=" + str(self.kernel_size) + ", p=" + "{:.4f}".format(self.p.data.tolist()[0]) + \
                ", eps=" + str(self.eps) + ")"

class CNN_NET_30(nn.Module):
    # Notes:
    # - training is more stable without BatchNorm, but resulting performance is worse
    def __init__(self, output_size: int,
                       flowstats_input_size: int,
                       ppi_input_channels: int,
                       use_flowstats: bool = True, use_ppi_as_flowstats: bool = False, use_ppi_chain: bool = False,
                       conv_normalization: NormLayerEnum = NormLayerEnum.BATCH_NORM, linear_normalization: NormLayerEnum = NormLayerEnum.BATCH_NORM,
                       cnn_channels1: int = 200, cnn_channels2: int = 300, cnn_channels3: int = 300, cnn_num_hidden: int = 3, cnn_depthwise: bool = False, cnn_pooling_dropout_rate: float = 0.1,
                       flowstats_size: int = 225, flowstats_out_size: int = 225, flowstats_num_hidden: int = 2, flowstats_dropout_rate: float = 0.1,
                       ppi_size: int = 225, ppi_out_size: int = 225, ppi_num_hidden: int = 2, ppi_dropout_rate: float = 0.1,
                       latent_size: int = 600, latent_num_hidden: int = 0, latent_dropout_rate: float = 0.2,
                       ):
        super().__init__()
        assert use_flowstats or not use_ppi_as_flowstats
        assert not (use_ppi_as_flowstats and use_ppi_chain)
        self.use_flowstats = use_flowstats
        self.use_ppi_as_flowstats = use_ppi_as_flowstats
        self.use_ppi_chain = use_ppi_chain
        self.output_size = output_size
        self.latent_size = latent_size
        self.layers_for_grad = []
        self.temperature: Optional[torch.Tensor] = None

        cnn_final_len = 10
        groups = ppi_input_channels if cnn_depthwise else 1
        ppi_flattened_size = ppi_input_channels * PPI_MAX_LEN
        flowstats_input_size = flowstats_input_size + ppi_flattened_size if use_ppi_as_flowstats else flowstats_input_size
        fc_shared_input_size = cnn_channels3
        if use_flowstats:
            fc_shared_input_size += flowstats_out_size
        if use_ppi_chain:
            fc_shared_input_size += ppi_out_size
        conv_norm_fn = partial(conv_norm_layer, normalization=conv_normalization)
        linear_norm_fn = partial(linear_norm_layer, normalization=linear_normalization)

        self.cnn = nn.Sequential(
            # [(W−K+2P)/S]+1
            # Input: 30 * 3
            nn.Conv1d(ppi_input_channels, cnn_channels1, kernel_size=7, stride=1, groups=groups, padding=3),
            nn.ReLU(inplace=False),
            *conv_norm_fn(cnn_channels1),

            # 30 x channels1
            *(nn.Sequential(
                nn.Conv1d(cnn_channels1, cnn_channels1, kernel_size=5, stride=1, groups=groups, padding=2),
                nn.ReLU(inplace=False),
                *conv_norm_fn(cnn_channels1),) for _ in range(cnn_num_hidden)),

            # 30 x channels1
            nn.Conv1d(cnn_channels1, cnn_channels2, kernel_size=5, stride=1),
            nn.ReLU(inplace=False),
            *conv_norm_fn(cnn_channels2),
            # 26 * channels2
            nn.Conv1d(cnn_channels2, cnn_channels2, kernel_size=5, stride=1),
            nn.ReLU(inplace=False),
            *conv_norm_fn(cnn_channels2),
            # 22 * channels2
            nn.Conv1d(cnn_channels2, cnn_channels3, kernel_size=4, stride=2),
            nn.ReLU(inplace=False),
            # 10 * channels3
        )
        self.cnn_global_pooling = nn.Sequential(
            GeM(kernel_size=cnn_final_len),
            nn.Flatten(),
            *linear_norm_fn(cnn_channels3),
            nn.Dropout(cnn_pooling_dropout_rate),
        )
        if self.use_ppi_chain:
            self.fc_ppi = nn.Sequential(
                nn.Linear(ppi_flattened_size, ppi_size),
                nn.ReLU(inplace=False),
                *linear_norm_fn(ppi_size),

                *(nn.Linear(ppi_size, ppi_size),
                nn.ReLU(inplace=False),
                *linear_norm_fn(ppi_size)) * ppi_num_hidden,

                nn.Linear(ppi_size, ppi_out_size),
                nn.ReLU(inplace=False),
                *linear_norm_fn(ppi_out_size),
                nn.Dropout(ppi_dropout_rate),
            )
        self.fc_flowstats = nn.Sequential(
            nn.Linear(flowstats_input_size, flowstats_size),
            nn.ReLU(inplace=False),
            *linear_norm_fn(flowstats_size),

            *(nn.Sequential(
                nn.Linear(flowstats_size, flowstats_size),
                nn.ReLU(inplace=False),
                *linear_norm_fn(flowstats_size)) for _ in range(flowstats_num_hidden)),

            nn.Linear(flowstats_size, flowstats_out_size),
            nn.ReLU(inplace=False),
            *linear_norm_fn(flowstats_out_size),
            nn.Dropout(flowstats_dropout_rate),
        )
        self.fc_shared = nn.Sequential(
            nn.Linear(fc_shared_input_size, latent_size),
            nn.ReLU(inplace=False),
            *linear_norm_fn(latent_size),
            nn.Dropout(latent_dropout_rate),

            *(nn.Sequential(
                nn.Linear(latent_size, latent_size),
                nn.ReLU(inplace=False),
                *linear_norm_fn(latent_size),
                nn.Dropout(latent_dropout_rate)) for _ in range(latent_num_hidden)),
        )
        self.out = nn.Linear(latent_size, output_size)

        for layer in self.layers_for_grad:
            setattr(self.fc_shared[layer], "samples_grad", True)

    def temperature_scale(self, logits):
        """
        Perform temperature scaling on logits
        """
        assert isinstance(self.temperature, torch.Tensor)
        # Expand temperature to match the size of logits
        temperature = self.temperature.unsqueeze(1).expand(logits.size(0), logits.size(1))
        return logits / temperature

    def forward(self, *t, react_threshold=None):
        if len(t) == 1:
            t = t[0]
        ppi, flowstats = t
        out_cnn = self.cnn(ppi)
        out_cnn = self.cnn_global_pooling(out_cnn)
        out = out_cnn
        if self.use_flowstats:
            if self.use_ppi_as_flowstats:
                flowstats_input = torch.column_stack([torch.flatten(ppi, 1), flowstats])
            else:
                flowstats_input = flowstats
            out_flowstats = self.fc_flowstats(flowstats_input)
            out = torch.column_stack([out, out_flowstats])
        if self.use_ppi_chain:
            out_ppi = self.fc_ppi(torch.flatten(ppi, 1))
            out = torch.column_stack([out, out_ppi])
        out = self.fc_shared(out)
        if react_threshold is not None:
            # out = out.clip(max=react_threshold) # one threshold
            out = torch.min(out, react_threshold) # threshold per activation
        logits = self.out(out)
        if not self.training and self.temperature:
            logits = self.temperature_scale(logits)
        return logits
