import numpy as np
import torch
import torchvision
import torchvision.transforms as transforms
import random
from scipy.spatial.distance import jensenshannon
from collections import Counter


def calculate_label_distribution(dataset, label_set=None):
    """
    Computes the label distribution (probability vector) of a dataset.
    dataset: List of labels.
    label_set: Optional fixed set of all possible labels (to ensure same dimension).
    """
    counter = Counter(dataset)
    if label_set is None:
        label_set = sorted(set(dataset))
    total = sum(counter.values())
    distribution = np.array([counter[label] / total for label in label_set])
    return distribution, label_set

def calculate_js_divergence(data1, data2):
    """
    Computes the Jensen-Shannon divergence between two datasets.
    Each dataset should be a list or array of class labels.
    """
    # Ensure both use the same label set
    all_labels = sorted(set(data1).union(set(data2)))

    dist1, _ = calculate_label_distribution(data1, all_labels)
    dist2, _ = calculate_label_distribution(data2, all_labels)

    # Use scipy's jensenshannon (returns sqrt(JS divergence), so we square it)
    js_div = jensenshannon(dist1, dist2, base=2.0) ** 2
    return js_div


CLASSES_PER_NON_IID_CLIENT = 2
NUM_CLIENTS = 10
NON_IID_CLIENTS_RATIO = 0.5

def partition_data_mixed_with_distribution(dataset, num_clients=10, noniid_clients_ratio=0.5, num_classes=10):
    data = np.array(dataset.data)
    targets = np.array(dataset.targets)

    noniid_clients = int(num_clients * noniid_clients_ratio)
    iid_clients = num_clients - noniid_clients

    client_indices_list = []

    # 1. IID clients
    all_indices = list(range(len(dataset)))
    random.shuffle(all_indices)
    iid_data_per_client = len(dataset) // num_clients

    for i in range(iid_clients):
        indices = all_indices[i * iid_data_per_client:(i + 1) * iid_data_per_client]
        client_indices_list.append(indices)

    class_indices = {i: np.where(targets == i)[0].tolist() for i in range(num_classes)}
    used_indices = set()

    for _ in range(noniid_clients):
        selected_classes = random.sample(range(num_classes), CLASSES_PER_NON_IID_CLIENT)
        client_indices = []

        for cls in selected_classes:
            available = list(set(class_indices[cls]) - used_indices)
            selected = random.sample(available, min(500, len(available)))
            client_indices.extend(selected)
            used_indices.update(selected)

        client_indices_list.append(client_indices)

    # Create DataLoaders (optional)
    client_loaders = []
    for indices in client_indices_list:
        subset = torch.utils.data.Subset(dataset, indices)
        loader = torch.utils.data.DataLoader(subset, batch_size=32, shuffle=True)
        client_loaders.append(loader)

    return client_loaders, client_indices_list, targets

# --- Main Execution ---
if __name__ == "__main__":
    # CIFAR-10 Transform and Load
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,))
    ])

    trainset = torchvision.datasets.CIFAR10(root='./data', train=True, download=True, transform=transform)

    # Partition the dataset
    client_loaders, client_indices_list, full_targets = partition_data_mixed_with_distribution(
        trainset, num_clients=NUM_CLIENTS, noniid_clients_ratio=NON_IID_CLIENTS_RATIO
    )

    # Full dataset labels
    global_labels = list(full_targets)

    # JS divergence between each client and global distribution
    print("\nJS Divergence (Client vs Global Distribution):")
    for i, indices in enumerate(client_indices_list):
        client_labels = [full_targets[j] for j in indices]
        js_div = calculate_js_divergence(client_labels, global_labels)
        print(f"Client {i:2d} -> JS Divergence: {js_div:.4f}")
